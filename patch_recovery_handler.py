#!/usr/bin/env python3
"""
Fault-recovery patch for the HiBy R1 album-art use-after-free crash.

Instead of validating the (undistinguishable) dangling cover pointer, this lets the
bad dereference fault and SURVIVES it: the player's own SIGSEGV handler (signal()-
registered at VA 0x70f640) is rewritten so that, when the fault is inside a known
cover-render function, it rewrites the saved PC in the signal context to that
function's clean epilogue -- aborting just that one cover-draw and resuming -- instead
of calling exit() (which makes the launch script reboot).

Safe by construction: it only redirects when a2 looks like a stack context AND the
saved PC sits in a known cover-render range; otherwise it falls through to the original
exit()/reboot path. Worst case = no change from today.

Covers the two observed crash sites:
  draw  0x004584c0 (fault 0x0045850c) -> epilogue 0x0045851c
  loop  0x004332c0 (fault 0x00433314) -> epilogue 0x00433350

Firmware base: 1.7b1 (use a build with signal handlers INTACT, e.g.
r1-1.7b1-mod-nocache-adb.upt -- NOT the -adb-log build, which NOPs the registrations).

Usage: python3 patch_recovery_handler.py <path_to_hiby_player>
"""
import struct, sys, os

HANDLER_VA   = 0x0070f640        # signal handler entry (addiu sp,sp,-0xa0)
PATCH_VA     = 0x0070f644        # we overwrite from here (the print section)
EXIT_VA      = 0x0070f72c        # original exit() call site (fall-through target)
TEXT_BASE    = 0x00400000

DRAW_LO, DRAW_HI, DRAW_EPI = 0x004584c0, 0x00458534, 0x0045851c
LOOP_LO, LOOP_HI, LOOP_EPI = 0x004332c0, 0x00433370, 0x00433350

# register numbers
ZERO, A2, T0, T1, T4, T5, T6, RA = 0, 6, 8, 9, 12, 13, 14, 31

# --- tiny MIPS assembler (only the forms we use) ---------------------------------
def R(rs,rt,rd,sa,fn):   return (rs<<21)|(rt<<16)|(rd<<11)|(sa<<6)|fn
def I(op,rs,rt,imm):     return (op<<26)|(rs<<21)|(rt<<16)|(imm&0xffff)
def J(op,tgt):           return (op<<26)|((tgt>>2)&0x03ffffff)
def srl(rd,rt,sa):       return R(0,rt,rd,sa,0x02)
def subu(rd,rs,rt):      return R(rs,rt,rd,0,0x23)
def jr(rs):              return R(rs,0,0,0,0x08)
def sltiu(rt,rs,imm):    return I(0x0b,rs,rt,imm)
def addiu(rt,rs,imm):    return I(0x09,rs,rt,imm)
def lw(rt,off,rs):       return I(0x23,rs,rt,off)
def sw(rt,off,rs):       return I(0x2b,rs,rt,off)
def lui(rt,imm):         return I(0x0f,0,rt,imm)
def ori(rt,rs,imm):      return I(0x0d,rs,rt,imm)
def nop():               return 0
def j(addr):             return J(0x02,addr)
def bnez(rs,off):        return I(0x05,rs,0,off)   # bne rs,zero,off  (off in words)

# Build the recovery as a list; branch targets resolved by label index.
def build():
    # we assemble symbolically: each entry is ('op', ...) and we patch branch offsets after
    code = []
    L = {}
    def emit(w): code.append(w)
    # 0: srl t0,a2,28
    emit(srl(T0,A2,28))
    # 1: sltiu t1,t0,7
    emit(sltiu(T1,T0,7))
    # 2: bnez t1,FALL   (offset filled later)
    bnez_fall = len(code); emit(0)
    # 3: nop (delay)
    emit(nop())
    # 4: lw t0,8(a2)
    emit(lw(T0,8,A2))
    # 5: lui t4,0x45
    emit(lui(T4,0x45))
    # 6: ori t4,t4,0x84c0  (0x4584c0)
    emit(ori(T4,T4,DRAW_LO & 0xffff))
    # 7: subu t5,t0,t4
    emit(subu(T5,T0,T4))
    # 8: sltiu t6,t5,(DRAW_HI-DRAW_LO)
    emit(sltiu(T6,T5,DRAW_HI-DRAW_LO))
    # 9: bnez t6,FDRAW
    bnez_draw = len(code); emit(0)
    # 10: lui t4,0x43  (delay, harmless)
    emit(lui(T4,0x43))
    # 11: ori t4,t4,0x32c0  (0x4332c0)
    emit(ori(T4,T4,LOOP_LO & 0xffff))
    # 12: subu t5,t0,t4
    emit(subu(T5,T0,T4))
    # 13: sltiu t6,t5,(LOOP_HI-LOOP_LO)
    emit(sltiu(T6,T5,LOOP_HI-LOOP_LO))
    # 14: bnez t6,FLOOP
    bnez_loop = len(code); emit(0)
    # 15: nop (delay)
    emit(nop())
    # 16: FALL: j EXIT_VA
    L['FALL']=len(code); emit(j(EXIT_VA))
    # 17: nop
    emit(nop())
    # 18: FDRAW: lui t4,0x45
    L['FDRAW']=len(code); emit(lui(T4,0x45))
    # 19: ori t4,t4,0x851c  (0x45851c)
    emit(ori(T4,T4,DRAW_EPI & 0xffff))
    # 20: sw t4,8(a2)
    emit(sw(T4,8,A2))
    # 21: jr ra
    emit(jr(RA))
    # 22: nop
    emit(nop())
    # 23: FLOOP: lui t4,0x43
    L['FLOOP']=len(code); emit(lui(T4,0x43))
    # 24: ori t4,t4,0x3350  (0x433350)
    emit(ori(T4,T4,LOOP_EPI & 0xffff))
    # 25: sw t4,8(a2)
    emit(sw(T4,8,A2))
    # 26: jr ra
    emit(jr(RA))
    # 27: nop
    emit(nop())
    # resolve branch offsets: off = target_idx - (branch_idx + 1)
    code[bnez_fall] = bnez(T1, L['FALL'] - (bnez_fall+1))
    code[bnez_draw] = bnez(T6, L['FDRAW'] - (bnez_draw+1))
    code[bnez_loop] = bnez(T6, L['FLOOP'] - (bnez_loop+1))
    return code

def patch(path):
    data = bytearray(open(path,'rb').read())
    hoff = HANDLER_VA - TEXT_BASE
    poff = PATCH_VA   - TEXT_BASE
    entry = struct.unpack_from('<I', data, hoff)[0]
    if entry != 0x27bdff60:   # addiu sp,sp,-0xa0
        # idempotency / wrong base check
        print(f"[!] handler entry @ {hex(HANDLER_VA)} = {entry:08x}, expected 27bdff60.")
        if struct.unpack_from('<I', data, poff)[0] == build()[0]:
            print("[+] already patched. nothing to do."); return True
        print("[!] unexpected bytes -- aborting."); return False
    code = build()
    blob = b''.join(struct.pack('<I', w) for w in code)
    if poff + len(blob) > (EXIT_VA - TEXT_BASE):
        print("[!] recovery code would overrun the exit() site -- aborting."); return False
    data[poff:poff+len(blob)] = blob
    bak = path + '.prepatch.bak'
    if os.path.exists(bak): os.remove(bak)
    os.rename(path, bak)
    open(path,'wb').write(data)
    os.chmod(path, 0o755)
    if sys.platform=='darwin':
        import subprocess; subprocess.run(['xattr','-c',path],capture_output=True)
    print(f"[+] recovery handler installed at {hex(PATCH_VA)} ({len(code)} instrs). backup: {bak}")
    return True

if __name__ == '__main__':
    sys.exit(0 if patch(sys.argv[1]) else 1)
