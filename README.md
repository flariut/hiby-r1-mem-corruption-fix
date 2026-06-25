# HiBy R1 — Album-Art Crash: Root Cause and Fault-Recovery Fix

A reverse-engineering writeup and a binary patch for the long-standing bug where the
HiBy R1 freezes and spontaneously reboots while browsing album art.

- **Device:** HiBy R1 (Ingenic X1600 / XBurst, MIPS32, little-endian, kernel 4.4.94+)
- **Firmware analysed:** R1 `1.7b1` (`hiby_player`, ELF32 MIPS LSB, stripped)
- **Class:** dereference of a dangling/stale cover-image pointer (SIGSEGV) under memory pressure
- **Symptom:** spontaneous reboot during normal library browsing
- **Status:** root-caused from kernel register dumps; a fault-recovery binary patch is provided that
  converts the crash into a harmlessly-skipped cover instead of a reboot

This was done by black-box testing and static/dynamic reverse engineering, with no source access.
All virtual addresses are specific to `1.7b1`.

> **Scope.** This is an unofficial, community fix. It modifies firmware HiBy did not author this
> patch for; flashing modified firmware is at your own risk. The primary intent is to document the
> defect precisely enough that it can be fixed upstream. A prebuilt image is provided for
> convenience; you can also build your own with the patch script.

---

## Contents

1. [Symptom](#1-symptom)
2. [Crash evidence](#2-crash-evidence)
3. [Root cause: a dangling cover-image pointer](#3-root-cause-a-dangling-cover-image-pointer)
4. [Why a value check cannot fix it](#4-why-a-value-check-cannot-fix-it)
5. [The fix: fault recovery](#5-the-fix-fault-recovery)
6. [Why this covers the consumers](#6-why-this-covers-the-consumers)
7. [Using the patch](#7-using-the-patch)
8. [Prebuilt firmware image](#8-prebuilt-firmware-image)
9. [Address anchors](#9-address-anchors)
10. [The proper upstream fix](#10-the-proper-upstream-fix)

---

## 1. Symptom

Browsing album art — the cover grid, or the full-resolution cover on the now-playing screen —
hangs for a fraction of a second and the device reboots. It is intermittent, correlated with load,
and worse on a cold boot or during the initial library scan. It is not tied to any particular
album, cover, resolution or format.

Enabling the on-card image cache (`tf_image_cache_enable`) reduces it, because a cache hit skips
the decode-and-draw path where the fault occurs — a side effect of the cause, not a fix.

---

## 2. Crash evidence

`hiby_player` installs its own signal handlers that catch the fault, print a useless one-line
backtrace and `exit()` — which is why the device just reboots and the logs say nothing. To get a
real dump we NOP'd those handlers, enabled `kernel.print-fatal-signals`, and captured `dmesg`
before the reboot. Two distinct crash sites were captured (faulting thread `system_main_thread`):

```
; crash A — the image-draw routine
epc   : 0045850c        ; lw a0, 0x50(s1)     (s1 = the cover pointer)
Cause : ExcCode 04      ; address error on load
$17(s1): 0007bbf6       ; not a pointer

; crash B — a cover-iteration loop
epc   : 00433314        ; lw v0, (v0)         (v0 = the cover pointer)
Cause : ExcCode 02      ; TLB load miss (unmapped)
$2(v0) : 1909f534       ; not a pointer
```

The faulting values vary wildly between crashes — `0x7bbf6` (≈½ MB), `0xdcfdd`, `0x1909f534`
(≈420 MB) — small and large, aligned and unaligned. In every case the renderer is dereferencing
the cover-image pointer field and that field holds a non-pointer, **unmapped** value.

---

## 3. Root cause: a dangling cover-image pointer

Each list row / cover descriptor has an image-pointer field at offset `+8`. The renderer reads it,
checks only that it is non-zero, and dereferences it (`lw a0, 0x50(coverPtr)` and similar). When
the field holds a stale/garbage value, that load faults.

Crucially, the field is **transient**: it is populated only while a cover is being decoded and
drawn, and cleared afterwards. Three separate live-memory scans of a settled, fully-populated grid
found **no** image object in any descriptor's `+8` — it is normally `0`.

The decode/allocation path is **clean**. The bitmap allocator (`0x43d560`), the JPEG/decode
routine (`0x427a40`), the cover-file descriptor builder (`0x427660`), and the relevant object
constructors all `free` and return `NULL` on failure. So the garbage is **not** a forgotten
NULL-on-failure. Combined with:

- the field being transient,
- the trigger being memory pressure,
- the faulting values being arbitrary and unmapped, and
- the crash occurring on the **main/render thread** while covers are decoded on a **separate parser
  thread** (`album_cover_parser`),

the defect is a **use-after-free / cross-thread lifecycle bug**: the transient image is freed (it
is short-lived, and pressure forces it), the `+8` reference to it is not cleared, and the render
thread dereferences the dangling pointer before it is cleared. `0x1909f534` is exactly what a freed
pointer looks like once its memory is reused or unmapped.

This is a *distributed* defect — a missing ownership/synchronization invariant spanning the parser's
set, the free, and the render read — not a single wrong instruction. That is why it is so hard to
pin to one line, and it is the reason a value-based fix cannot work.

---

## 4. Why a value check cannot fix it

You cannot tell a dangling pointer from a valid one by inspecting the value. A freed address can be
**any** value, of **any** magnitude, with **any** alignment — and we confirmed this empirically:

- an `== file size` / `== sibling field` equality check let a crash through;
- an `address < 0x00400000` range check blanked valid covers (a real cover buffer can live in a low
  memory pool) **and** missed large garbage like `0x1909f534`;
- a `4-byte aligned` check (valid pointers must be aligned) still let `0x1909f534` (which is aligned)
  through.

There is no property of the stored value that separates a live cover pointer from a freed one. The
only thing that distinguishes them is whether the address is **currently mapped** — which is exactly
what the CPU tells us when the load faults.

---

## 5. The fix: fault recovery

So instead of trying to validate the (undistinguishable) pointer, we let the bad dereference fault
and **survive it**.

The device reboots not because of the fault, but because the player's `SIGSEGV` handler (registered
via `signal()` at `0x70f640`) calls `exit()`, and the launch script reboots on exit. Every one of
these crashes passes through that one handler. We rewrite it so that, when the fault is inside a
known cover-render function, it **rewrites the saved program counter in the signal context to that
function's clean epilogue** — forcing a tidy early return that aborts just that one cover-draw — and
resumes, instead of exiting:

```
on SIGSEGV (a2 = signal context):
    if a2 is not a stack address      -> original exit()  (reboot, unchanged)
    pc = saved_PC (a2 + 8)
    if pc in draw  [0x4584c0,0x458534) -> saved_PC = 0x45851c   ; draw epilogue
    if pc in loop  [0x4332c0,0x433370) -> saved_PC = 0x433350   ; loop epilogue
    else                               -> original exit()  (reboot, unchanged)
    return -> kernel resumes at the epilogue -> bad cover skipped, no reboot
```

The cover that would have crashed simply renders blank/missing; everything else continues. The two
ranges correspond to the two captured crash sites (the draw routine `0x4584c0` and the cover loop
`0x4332c0`); their clean epilogues are `0x45851c` and `0x433350`.

**Safe by construction.** The handler only redirects when `a2` looks like a stack context *and* the
saved PC sits in a known cover-render range; any other fault falls through to the original
`exit()`/reboot path. Worst case is identical to today's behaviour — it cannot make things worse,
and it does not mask unrelated crashes.

The patch reuses the handler's own (now-unused) print/backtrace code space, so there is no need to
find spare room elsewhere in the binary.

---

## 6. Why this covers the consumers

Cover dereferences come in two shapes:

- **Draw-based (most of them).** Every UI screen that *draws* a cover — the album grid, the
  now-playing blurred background, and so on — passes the cover pointer to the shared draw routine
  `0x4584c0`, which dereferences it at **the single instruction `0x45850c`**. However many callers
  there are, they all crash at that one site, so the draw-range recovery covers all of them at once.
- **Direct dereference.** Code that loads the cover `+8` and dereferences it in place, like the loop
  at `0x433314`. Each is its own site; the one observed is covered by the loop range.

If a different direct-dereference site ever surfaces, it shows up as a reboot, and its address is
added to the table. (The `+8`-then-dereference shape is too generic across the stripped binary to
enumerate the cover-specific ones statically with confidence.)

---

## 7. Using the patch

`patch_recovery_handler.py` rewrites the signal handler in an extracted `hiby_player` binary.

```
python3 patch_recovery_handler.py <path_to_hiby_player>
```

It must be applied to a build whose **signal handlers are intact** (a normal firmware, not a
diagnostic build that NOP'd the handler registration). It is idempotent and keeps a
`.prepatch.bak` backup.

**Verification:** disassemble `0x70f644`; it should read `srl t0,a2,0x1c` followed by the two
range checks and the two `sw t4, 8(a2)` epilogue writes (to `0x45851c` and `0x433350`), with a
`j 0x70f72c` fall-through to the original `exit()`.

---

## 8. Prebuilt firmware image

A ready-to-flash image with the fix applied:

**`r1-1.7b1-mod-coverfix.upt`**

- Size: 39,856,128 bytes
- MD5: `cb6d3829adc461e040c9eb83a6e1c9d4`

It is the stock HiBy R1 `1.7b1` firmware plus a small, deliberate set of changes:

| Change | State | Why |
| :--- | :--- | :--- |
| **Fault-recovery handler** | Applied | The fix from this repository (sections 3–6). |
| **Cover image cache** (`tf_image_cache_enable`) | Off | Only ever hid the crash; with faults recovered it is unnecessary. |
| **Music database on the card** (`tf_music_db_enable`) | On | Exposes the option in settings to keep the scanned DB on the microSD card; changes nothing unless you enable it in the UI. |
| **UI fonts** | Patched | Non-ASCII titles render correctly. Inherited from the `1.7b1-mod` base. |

**Flashing:** copy the `.upt` to the microSD card as `r1.upt` and apply it from the player's
firmware-update menu. Keep a known-good stock `.upt` as a recovery path. Flashing modified firmware
is at your own risk and is not endorsed by HiBy.

---

## 9. Address anchors

For `1.7b1` only.

| VA | Role |
| :--- | :--- |
| `0x0045850c` | crash A — `lw a0,0x50(s1)` in the image-draw routine `0x004584c0`; epilogue `0x0045851c` |
| `0x00433314` | crash B — `lw v0,(v0)` in the cover-iteration loop `0x004332c0`; epilogue `0x00433350` |
| `0x0070f640` | the `signal()`-registered crash handler (rewritten into the recovery handler) |
| `0x0042827c` | `album_cover_parser` copy of the cover descriptor into the list item |
| `0x004409e0` / `0x00454040` | the cover-manager getter (locked wrapper / raw accessor) |
| `0x00466bc0` / `0x00466cc0` | app `free` wrappers |

---

## 10. The proper upstream fix

The fault-recovery handler is a robust **mitigation** — it stops the reboots without needing to
pinpoint the exact lifecycle bug. The real fix belongs in HiBy's source, where the thread/ownership
structure is visible with symbols:

1. **Clear the back-reference on free.** When the transient cover image is freed, set the descriptor
   `+8` (and any copy in the list item) to `NULL` before the memory is released, so no dangling
   reference survives.
2. **Synchronize the parser and render threads.** The cover descriptors are produced on
   `album_cover_parser` and consumed on the main render thread; the read of `+8` and the
   free/replace of the image must not race.
3. **Validate at the consumer as defence in depth.** The renderer already skips `coverPtr == 0`;
   pairing that with proper ownership above removes the crash class entirely.

The in-process signal handlers also currently mask faults like this from any crash log. Recording
the faulting PC and registers before terminating would let issues like this surface in QA instead of
being silently swallowed.
