# HiBy R1 — Album-Art Memory-Corruption Crash: Root Cause and Fix

A reverse-engineering writeup and a one-instruction binary patch for the long-standing
bug where the HiBy R1 freezes and spontaneously reboots while scrolling the album library.

- **Device:** HiBy R1 (Ingenic X1600 / XBurst, MIPS32, little-endian, kernel 4.4.94+)
- **Firmware analysed:** R1 `1.7b1` (`hiby_player`, ELF32 MIPS LSB, stripped)
- **Class:** invalid-pointer dereference (SIGSEGV) on the album-art rendering path, triggered by memory pressure
- **Symptom:** spontaneous reboot during normal library browsing
- **Status:** root-caused from a kernel register dump; a single-site binary patch was built and verified on-device

This work was done by black-box testing plus static reverse engineering, with no source
access. All virtual addresses are specific to `1.7b1` and are anchors only; the durable,
source-locating clues are the symbol strings and struct offsets in section 7.

> **Scope and disclaimer.** This is an unofficial, community fix. It modifies firmware that
> HiBy did not author this patch for. Flashing modified firmware is at your own risk. The
> primary intent of this repository is to document the defect precisely enough that it can be
> fixed upstream. A prebuilt, ready-to-flash image is provided for convenience (see
> [section 9](#9-prebuilt-firmware-image)); you can also build your own with the patch script.

---

## Table of contents

- [Evidence status — proven vs. empirical vs. conjecture](#evidence-status--proven-vs-empirical-vs-conjecture)
1. [What you see as a user](#1-what-you-see-as-a-user)
2. [The investigation](#2-the-investigation)
3. [Crash evidence (kernel register dump)](#3-crash-evidence-kernel-register-dump)
4. [Root cause](#4-root-cause)
5. [Why it is intermittent](#5-why-it-is-intermittent)
6. [The fix and what it proves](#6-the-fix-and-what-it-proves)
7. [Symbols, strings and structures](#7-symbols-strings-and-structures)
8. [Using the patch](#8-using-the-patch)
9. [Prebuilt firmware image](#9-prebuilt-firmware-image)
10. [Address anchors (version-specific)](#10-address-anchors-version-specific)
11. [Appendix A — conjectured source logic](#appendix-a--conjectured-source-logic)
12. [Appendix B — recommended source-level fixes](#appendix-b--recommended-source-level-fixes)

---

## Evidence status — proven vs. empirical vs. conjecture

This writeup deliberately separates three tiers of certainty. Read every claim in light of which
tier it sits in; the body text is tagged accordingly.

**Evidence-backed (hard).** Verified directly from the stripped binary — radare2 disassembly and
the Ghidra decompiler (`r2ghidra` / `pdg`) — and from the kernel register dump:

- **The fault.** `0x0045850c  lw a0, 0x50(s1)` dereferences `s1 = 0x7bbf6`, a value below the
  user-space base `0x00400000` → SIGSEGV. *(register dump)*
- **The propagation.** `s1` is `item+8`, loaded by the caller at `0x00436704  lw a0, 8(item)` and
  passed to the draw routine, which dereferences it. The caller's **only** guard on `item+8` is
  `== 0` (`0x004366a8  beqz`); there is no range or type check, and the draw routine validates
  nothing. *(disassembly)*
- **The store.** `item+8` is written by the copy at `0x0042827c`. Decompiled, that copy is
  `item.{+4,+8,+0xc,+0x10} = cover.{[1],[2],[3],[4]}` — a four-field struct copy that does not
  validate the pointer field. *(Ghidra)*
- **It is not the file size.** `0x7bbf6 = 506,870` is far larger than any compressed cover:
  measured across the test library, the largest cover is 129,799 bytes and none is within
  hundreds of KB of this value. *(measurement)*
- **The blamed allocator is innocent.** The decode/scale bitmap allocator `0x0043d560` is
  **clean** — it frees and returns NULL on allocation failure, and stores a *width* (≤ 65535,
  not a pointer) at `+8`. It cannot produce a non-null bad struct. *(Ghidra — this corrects
  earlier drafts, including a separate AI analysis, that blamed this routine.)*
- **The real producer is virtual.** The struct that is copied comes from a runtime virtual call:
  `0x004409e0` wraps `(*(obj+0x2c))(obj, …)` with `obj = *0x8ce0ec`, a BSS / runtime-initialised
  global. The producing assignment is therefore **not reachable by static analysis**. *(Ghidra +
  symbol table)*

**Empirical (behavioral).** Established by the patched firmware's behaviour on-device, *not* by
reading instructions:

- On a failed decode, `cover[+4] == cover[+8]`; on a success they differ. The fix gates purely on
  `+4 == +8`, and it both stops every crash **and** never blanks a valid cover — which a wrong
  signature could not do simultaneously. This is strong but indirect, and **cannot currently be
  proven statically**, because the producing code is behind the runtime virtual dispatch above.
- "No reboots since" is consistent with a correct fix, but on its own is also consistent with luck
  on a rare trigger. The signature argument above is what makes it more than luck — not the uptime.

**Conjecture / assumption (labelled as such wherever it appears).**

- *What* the shared `+4`/`+8` value is. Its ~½ MB magnitude is consistent with a **decoded** image
  buffer size (a failed `malloc` argument), not the compressed file — but the exact quantity is not
  pinned, and the producer is not statically reachable, so this stays a conjecture.
- The reconstructed C in [Appendix A](#appendix-a--conjectured-source-logic). It models the observed
  behaviour; it is **not** claimed to be the actual source.

The decisive way to promote the empirical item to hard evidence is a runtime probe: a diagnostic
hook at `0x0042827c` that records `+4`/`+8` through the same kernel-dump mechanism that produced the
original crash log. Static disassembly alone cannot reach the producer.

---

## 1. What you see as a user

Scroll the album view (the cover grid), the screen hangs for a fraction of a second, and the
device reboots. It is intermittent, correlated with load, and worse on a cold boot or during
the initial library scan. It is not tied to a particular album or cover.

Things that look like a cause but are not:

- **Cover resolution or format.** Reproduced with baseline JPEG, PNG and BMP, at 600, 480, 240
  and 120 px. Re-encoding the entire library does not help.
- **The microSD card.** Tested and ruled out.
- **The battery, or a memory leak, or the kernel OOM-killer.** None of these. The register dump
  in section 3 shows a clean userspace SIGSEGV.

One thing that *does* reliably reduce it: enabling the on-card image cache
(`tf_image_cache_enable`). Section 5 explains why that is a side effect of the real cause, not a
real fix.

---

## 2. The investigation

The R1 runs a stripped MIPS `hiby_player` binary on a small Ingenic SoC with about 57 MB of RAM
and no swap. Two things made this bug survive for years.

**First, the application hides its own crashes.** `hiby_player` installs its own
SIGSEGV/SIGBUS/SIGUSR1 handlers that catch the fault, print a truncated one-line backtrace, and
exit. The captured process output is just:

```log
HiBy Player crashed by signal SIGSEGV.
Call Trace:
	/usr/bin/hiby_player() [0x70f6ac]
```

```log
HiBy Player crashed by signal SIGUSR1.
Call Trace:
	/usr/bin/hiby_player() [0x70f6ac]
```

That single frame tells you nothing about where the fault actually happened. The handler swallows
the register state before it can reach the system log. To get a real dump we had to NOP those
handler registrations and enable `kernel.print-fatal-signals`, then stream `/proc/kmsg` and dump
`dmesg` to flash before the reboot (there is no pstore/ramoops, so post-mortem logs do not survive
a reboot otherwise).

**Second, the crash is non-deterministic.** It only fires under memory pressure (section 5), so it
cannot be reproduced on demand. That is the defining property of this whole class of bug, and it is
exactly why "random reboot" reports are easy to dismiss and hard to action. The randomness was the
symptom, not noise.

---

## 3. Crash evidence (kernel register dump)

Captured after disabling the in-process signal handlers (faulting thread `system_main_thread`):

```
potentially unexpected fatal signal 11.
CPU: 0 PID: 963 Comm: system_main_thr  4.4.94+ #1108
$ 4 (a0) : 0007bbf6      $17 (s1) : 0007bbf6
epc   : 0045850c        ra : 00436710
Status: 00001c13  USER EXL IE
Cause : 40808010 (ExcCode 04)        ; address error on load
BadVA : 0007bc46                     ; = s1(0x7bbf6) + 0x50
PrId  : 00d00000 (Xburst)
```

Reading the dump:

- `epc = 0x0045850c` is the instruction `lw a0, 0x50(s1)` inside the image-draw routine.
- `s1 = a0 = 0x0007bbf6` is the value being used as the image pointer.
- `0x0007bbf6 = 506,870` is a plain integer, not a valid address. It is **far too large to be the
  compressed cover file** — measured across the test library, the largest cover on the card is
  ~130 KB and none is anywhere near 506 KB — and it sits in the size range of a *decoded* image
  buffer. Its exact provenance is not proven; what is certain is that a non-pointer number occupies
  the slot where the decoded-image pointer belongs.
- `0x7bbf6 < 0x00400000` (below the MIPS user text base), so the load address-faults
  (`ExcCode 04`, address error on load; `BadVA = s1 + 0x50`).

The faulting address being a small integer rather than a plausible heap address is the whole case
in one line: the renderer is dereferencing a number that was never a pointer.

---

## 4. Root cause

The cover for a list row is produced by the album-art parser thread (the binary contains the
strings `album_cover_parser` and `cover_parser`). On the success path it copies the decoded image
descriptor into the list-item structure. The relevant store block:

```asm
; fcn.00427ee0  (album_cover_parser).  s3 = decode-result struct, s0+0x538 -> list item
0x00428270  lw v1, 8(s3)      ; v1 = result[+8]  (image-buffer pointer)
0x00428274  lw v0, 0x538(s0)  ; v0 = the list item
0x00428278  move a0, zero
0x0042827c  sw v1, 8(v0)      ; item[+8] = result[+8]      <-- the bug: stored unvalidated
0x00428280  lw v1, 0x10(s3)   ; result[+0x10]
0x00428284  lw v0, 0x538(s0)
0x00428288  sw v1, 0x10(v0)   ; item[+0x10] = result[+0x10]
```

Decompiled (Ghidra), the copy is unambiguous — a four-field struct copy with no validation:

```c
// fcn.00427ee0 (album_cover_parser); arg1 = parser "this", puVar24 = the cover struct
if ((*(arg1 + 0x530) == 0) && (*(arg1 + 0x538) != 0)) {     // item = arg1[0x538]
    *(*(arg1 + 0x538) + 0xc)  = puVar24[3];
    *(*(arg1 + 0x538) + 8)    = puVar24[2];   // item+8  = cover[+8]   <-- the bug
    *(*(arg1 + 0x538) + 0x10) = puVar24[4];
    *(*(arg1 + 0x538) + 4)    = puVar24[1];   // item+4  = cover[+4]
}
```

The only guard before this copy is `cover (puVar24) != NULL`. The field `cover[+8]` itself is never
validated. When the decode fails part-way, `cover` is a valid (non-null) struct, but `cover[+8]`
holds a non-pointer integer rather than a real buffer pointer. That value is copied into `item[+8]`,
and the renderer later executes the fatal `lw a0, 0x50(item[+8])` at `0x0045850c`. **This — the
unvalidated copy of `cover[+8]` into the list item — is the proven defect.**

**Where the bad value originates (not statically resolvable).** Earlier drafts of this document
(and a separate AI-assisted analysis) blamed the visible decode/scale chain
(`0x00427e40 → 0x00427a40 → 0x0043d560`) for "forgetting to null the field." Decompilation
disproves that: `0x0043d560` frees and returns **NULL** on allocation failure, and its `+8` is a
*width* (≤ 65535), not a pointer — so it cannot be the source of a non-null bad struct, and it is
not even the struct that gets copied. The struct that *is* copied (`puVar24`) is produced by a
**runtime virtual call** — `0x004409e0` invokes `(*(obj+0x2c))(obj, …)` where `obj = *0x8ce0ec`, a
BSS / runtime-initialised global. Because the target is a function pointer set at runtime, **the
producing assignment cannot be reached by static disassembly.** What we can state as fact is the
defect at the consumer (`0x0042827c`); the producer-side detail (see [Appendix A](#appendix-a--conjectured-source-logic))
is conjecture until captured at runtime.

Two guards should have caught this and both miss it:

1. **(proven)** the renderer checks the cover pointer for `== 0` (`0x004366a8`), but the bad value
   is non-zero, so it sails through and is dereferenced;
2. **(inferred)** the producing path leaves a non-pointer value in `cover[+8]` on failure instead of
   NULL — consistent with the evidence, but not provable statically because that path is virtual.

---

## 5. Why it is intermittent

- Total RAM is about 57 MB with no swap (`/proc/swaps` empty). The `hiby_player` resident set is
  about 18 to 20 MB, leaving roughly 12 MB free while browsing.
- Each cover decode transiently needs a few MB (a decoded bitmap plus a blurred copy — see the
  `img_table` schema in section 7, which stores both `data` and `blurred_data` per cover). Under
  fast scrolling or the cold-boot library scan, concurrent decodes push free memory low and a
  decode-buffer allocation fails.
- That allocation failure is the unchecked path that leaves a non-pointer value in the cover-pointer
  field.
- This is exactly why enabling the on-card image cache hides the crash: a cache *hit* skips
  decoding entirely, so the failing allocation never runs.

So the crash is rare, load-correlated, worse on cold boot, and masked by the cache — all of which
fall out of one fact: the decode buffer only fails to allocate when free RAM is tight.

---

## 6. The fix and what it proves

The defect can be neutralised at a single instruction: the store at `0x0042827c`. We redirect that
store to a small validation hook placed in `.text` dead space. The hook compares the
image-pointer field `result[+8]` against the companion field `result[+4]` and, when they are equal,
writes 0 instead of the bad value:

```asm
hook:
    lw    t0, 4(s3)     ; result[+4]  (companion field; equal to +8 on a failed decode)
    lw    t1, 8(s3)     ; result[+8]  (image pointer, or the leftover value on a failed decode)
    xor   t0, t0, t1    ; 0 iff the two fields are equal
    movz  t1, zero, t0  ; if equal (failed decode), force the pointer to 0
    sw    t1, 8(v0)     ; item[+8] = sanitised value
    j     0x00428284    ; rejoin original flow
    nop
```

The renderer's existing `coverPtr == 0` check then makes a sanitised cover render blank instead of
crashing. Because the value is fixed *at its source*, this single patched instruction protects
every one of the ~50 draw call sites that dereference a cover pointer (the album list, the
now-playing blurred background, and so on), not just the album view.

**Why the comparison, and not a range check.** An earlier attempt flagged invalid pointers by
testing `address < 0x00400000`. That blanked *all* valid covers, because the Ingenic Linux
platform maps shared libraries and dynamic heaps/memory pools in the low user-space range below
`0x00400000` (e.g. `$gp`/`r28` loads at `0x160000`–`0x1c0000`), so legitimately decoded image
structures live there too. The `result[+4] == result[+8]` comparison is robust: it keys on the
actual failure signature, not on an address range.

**What the fix demonstrates (empirical, not a static proof).** The hook gates purely on
`cover[+4] == cover[+8]`. It both stops every crash and never blanks a successfully decoded cover.
A wrong signature could not do both at once — too narrow and crashes would continue; too broad and
valid covers would blank. So the behaviour is strong evidence for two facts about the failure path:

- on a **failed** decode, `cover[+4]` and `cover[+8]` hold the **same** value; and
- on a **successful** decode they **differ** (`cover[+8]` is a real pointer, e.g. `0x00ee6b58`).

This is **empirical, not proven from the instructions.** The code that writes `cover[+4]` and
`cover[+8]` is behind a runtime virtual dispatch (`0x004409e0 → *(obj+0x2c)`, see section 4), so the
equality cannot be confirmed statically — only by the fix's behaviour, or by a runtime probe. What
the shared value *is* — a size, a length, a scratch quantity — is likewise not proven; its magnitude
(~½ MB) is consistent with a decoded image buffer and rules out the compressed cover file, but that
remains a conjecture (Appendix A). The hard, instruction-level facts are the fault, the unvalidated
copy, and the `== 0`-only guard (sections 3–4); the `+4 == +8` *signature* is empirical.

### A note on hook placement (the cause of an early boot loop)

The hook must be placed in **post-return dead space**, not just any run of zero bytes. The first
version of the patch placed the hook's first instruction (a faulting memory load) directly in the
**delay slot of a preceding `jr ra`**. Every time that unrelated function returned, the CPU
executed the load with a garbage `s3` and faulted, which crashed the player during the boot-time
cover scan and produced a **reboot loop**.

The patch script avoids this by locating a zero run whose immediately preceding word is an
unconditional control transfer (`jr ra` = `0800e003`, or `j`/`jal`). The run's first word is that
transfer's delay slot and is left as a `nop`; the hook is placed at `run_start + 4`. This
guarantees the hook's first instruction is never executed as a delay slot and is never reached by
fall-through — it is entered only via the `j <hook>` redirect. The chosen slot must be inside the
executable segment (`LOAD0`, `-r-x`, VA `0x00400000`–`0x00854180`). The `t0`/`t1` registers the
hook uses are dead at the store site, so it does not need to save or restore them.

### Patch encoding

| Site | Original (LE) | Patched (LE) |
| :--- | :--- | :--- |
| `0x0042827c` store | `08 00 43 ac` (`sw v1,8(v0)`) | `j <hook>` = `0x08000000 \| (hook_va>>2)` |
| hook (28 bytes) | 32-byte zero padding | the 7 instructions above |

The script locates the buggy store **by byte signature**, not a hard-coded offset, finds its own
safe padding block, and computes the rejoin and hook-jump targets, so it survives minor address
shifts between firmware builds. It is idempotent.

---

## 7. Symbols, strings and structures

For anyone (including HiBy's own engineers) trying to locate this in source. The identifier
strings below are present in the binary and most likely match the original source names.

| String / symbol | Where it points |
| :--- | :--- |
| `album_cover_parser`, `cover_parser` | the parser that stores the bad pointer (root site) |
| `system_main_thread` | the thread that crashes (`Comm: system_main_thr`) |
| `save_http_album_cover_fail` | a cover-load failure log in the same parser family |
| `------------- CACHE YES` / `------------- CACHE NO` | cache hit/miss log in the cover-list loader |
| `tf_image_cache_enable` | config flag that gates the on-card image cache (hides the bug) |
| `lg_image_cache_db_init`, `lg_image_cache_insert_table`, `lg_image_cache_select`, `lg_image_cache_is_exit`, `image_cache_sqlite3_prepare` | the SQLite image-cache module |
| `tf_music_db_enable`, `usrlocal_media.db`, `../src/music_db_v2.c` | media-DB module (note the leaked source path) |
| `with %d x %d thumbnail image` | thumbnail/decode logging |
| `playing_plane_iv_back` | now-playing blurred-cover background (also dereferences the cover ptr) |
| `lg_system` | logging tag around these paths |

Image-cache table schema (DDL string in the binary). Note `data` plus `blurred_data`, i.e. two
bitmaps held per cover, which is the per-cover memory cost referenced in section 5:

```sql
CREATE TABLE img_table (path TEXT COLLATE NOCASE, width INT, height INT, rgb_bit INT,
  data_size INT, data BLOB, blurred_data_size INT, blurred_data BLOB,
  PRIMARY KEY(path,rgb_bit,width,height));
```

Structure offsets observed (for cross-checking against the original structs):

- **List item / row:** field at `+0x04`, image pointer at `+0x08` (the crash field), field at
  `+0x0c`, field at `+0x10`, "cover loaded" flag at `+0x53c` in the parser's `this`.
- **Decode-result descriptor:** `data` at `[0]`/`+0`, a field at `[1]`/`+4` (equal to `+8` on a
  failed decode), image-buffer pointer at `[2]`/`+8` (holds a non-pointer value on failure), then
  `+0xc` and `+0x10`. The `+4`/`+8` labels of "size" and "pointer" are inferred from the success
  path and the sibling allocator; only the offsets and the failure-time equality are directly
  observed.
- **Image object dereferenced by the renderer:** pixel/data pointer at `+0x50` (the `lw a0,0x50(s1)`
  that faults).

Environment: `MemTotal` about 57 MB, no swap. `hiby_player` has `oom_score = 255` (it is the
designated OOM victim, but the kernel OOM-killer is not involved here — this is a userspace
SIGSEGV, confirmed by the register dump). `panic_on_oom = 0`. No pstore/ramoops.

---

## 8. Using the patch

`patch_player_source_fix.py` applies the single-site fix to an extracted `hiby_player` binary.

```
python3 patch_player_source_fix.py <path_to_hiby_player>
```

What it does:

- finds the buggy store by byte signature (resilient to minor address shifts; idempotent);
- finds a safe, post-return dead-space slot for the hook;
- writes the 28-byte validation hook and redirects the store to it;
- keeps a `.prepatch.bak` backup next to the binary;
- sets the binary executable (`0o755`) and, on macOS, clears extended attributes so the
  permissions are not flattened when the rootfs is repacked with `mksquashfs`.

If you build it yourself, you are responsible for extracting `hiby_player` from the firmware
image, repacking the SquashFS rootfs, and reflashing. If you would rather not, a prebuilt image
that already has this patch applied is provided in [section 9](#9-prebuilt-firmware-image).

**Verification checklist:**

- Disassemble the patched binary: `0x0042827c` now reads `j <hook>`; the hook disassembles to the 7
  instructions in section 6; the rejoin target equals the original `0x00428284` (or its shifted
  equivalent).
- Placement check: the word immediately before the hook is `nop`, and the word before *that* is a
  control transfer (`jr ra`/`j`). The hook VA is inside `LOAD0` (`-r-x`).
- Permissions: `hiby_player` is `-rwxr-xr-x` and macOS xattrs are stripped before `mksquashfs`.
- On device: scroll the album list with a cold cache (which forces decodes and failures). Covers
  that previously rebooted the unit now render blank at worst.

---

## 9. Prebuilt firmware image

For convenience, a ready-to-flash image with the fix already applied is published on the
repository's [Releases page](../../releases/latest):

**`r1-1.7b1-mod-coverfix.upt`**

- Size: 39,856,128 bytes
- MD5: `4dfeb816ef87eb8ed6ea0253161fb05a`

### What is in it

This is the stock HiBy R1 `1.7b1` firmware with a small, deliberate set of changes and nothing
else. It is built from HiBy's own `1.7b1` release; it is not a from-scratch ROM.

| Change | State in this image | Why |
| :--- | :--- | :--- |
| **Album-art crash patch** | Applied | The single-instruction source fix from this repository (sections 4–6). This is the whole point of the image. |
| **Cover image cache** (`tf_image_cache_enable`) | **Off** | The cache was only ever a *workaround* that hid the crash by skipping decodes. With the bug actually fixed it is no longer needed, and leaving it off keeps RAM pressure and SD writes down. |
| **Music database on the card** (`tf_music_db_enable`) | **On** | This only **makes the option available** in the player's settings; it does not move the database by itself. With it enabled you can choose, in the UI, to store the scanned music database (`usrlocal_media.db`) on the microSD card instead of internal storage. If you never enable it in the UI, nothing changes. It does not turn the library feature on or off; it only exposes where the index can live. |
| **UI font** | MiSans (`MiSans.ttf`) | So album and track titles with non-ASCII characters (CJK, accented Latin, and similar) render correctly instead of as boxes. This is inherited from the `1.7b1-mod` base. |

### What is deliberately NOT in it

This is a clean image for everyday use, not the diagnostic build that was used to capture the
crash dump. Specifically, it does **not** contain:

- **The signal-handler NOP patches.** `hiby_player`'s own SIGSEGV/SIGBUS/SIGUSR1 handlers are
  left intact (stock). Those were NOP'd only to force the kernel to print a register dump during
  diagnosis; there is no reason to ship that.
- **The debug launch script.** `hiby_player.sh` is the stock script. The diagnostic build
  rewrote it to enable `print-fatal-signals`, redirect stdout/stderr to flash, and dump `dmesg`
  before reboot. None of that is here.
- **adb / USB debugging changes.** Nothing in this image enables adb.

In other words: stock `1.7b1`, plus the MiSans font, plus the crash fix, with the music database
kept on the card and the cover cache off. No logging, no debug hooks, no adb.

### Building this image yourself

It was produced from `r1-1.7b1-mod.upt` (the MiSans-font base) by:

1. unpacking the rootfs (`unsquashfs`);
2. setting `tf_image_cache_enable` to `0` and `tf_music_db_enable` to `1` in
   `usr/resource/config.json`;
3. running `patch_player_source_fix.py` on `usr/bin/hiby_player` and removing the `.prepatch.bak`
   it leaves behind;
4. repacking the rootfs (`mksquashfs`, lzo, 128 KB blocks) and rebuilding the chunked,
   md5-chained `.upt` (ISO9660 with the `ota_v0/` layout).

The verification checklist in [section 8](#8-using-the-patch) was run against the repacked image:
the store at `0x42827c` reads `j 0x411ba4`, the hook is correct and sits in post-return dead
space, the three signal-handler `jal`s are unchanged, and the rootfs md5 matches `img_md5` in
`ota_update.in`.

### Flashing

Standard HiBy update procedure: copy the `.upt` to the microSD card and apply it from the
player's firmware-update menu. Keep a known-good stock `.upt` and a recovery path first.

> Flashing modified firmware is at your own risk and is not endorsed by HiBy. The safest outcome
> remains an official upstream fix.

---

## 10. Address anchors (version-specific)

For `1.7b1` only. These are reference points; the patch does not depend on them.

| VA | Role |
| :--- | :--- |
| `0x0045850c` | crash instruction `lw a0,0x50(s1)` in the image-draw routine `0x004584c0` |
| `0x00436660` | album-list renderer (the immediate caller, `ra=0x436710`); the `coverPtr==0` guard is at `0x004366a8` |
| `0x00427ee0` | `album_cover_parser`; the unchecked struct copy is at `0x0042827c` |
| `0x004409e0` | the actual cover-struct producer — a lock/unlock wrapper around the **virtual call** `(*(obj+0x2c))(obj,…)`, `obj = *0x8ce0ec` (BSS, runtime-init); not statically resolvable |
| `0x0043d560` | decode/scale bitmap allocator — **clean** (NULL on failure, `+8`=width); *not* the culprit, despite earlier drafts |
| `0x00427e40` -> `0x00427a40` | the visible decode/scale chain (calls `0x0043d560`); investigated and ruled out as the producer |
| `0x00466c20` / `0x00466bc0` | app `malloc` / `free` wrappers |
| `0x008ce0ec` / `0x008ce0f4` | global cover-manager object pointer / its lock (runtime-initialised) |

---

## Appendix A — conjectured source logic

Everything above this point is observed on-device or verified by the patch. This appendix is the
one part that is conjecture: a plausible reconstruction of the C that would produce the observed
behaviour, offered to help locate the code, not as a claim about the actual source.

> **Why this stays conjecture.** The code that writes `cover[+4]` and `cover[+8]` is reached through
> a runtime virtual call (`0x004409e0 → *(obj+0x2c)`, `obj = *0x8ce0ec`; see section 4). The target
> is a function pointer set at runtime, so the producing routine is **not reachable by static
> disassembly** — we cannot point at the instruction that seeds `+8`. The model below is therefore a
> behavioural reconstruction, not a located function. (Note: a separate AI-assisted pass claimed to
> have found this code with "100% hard evidence" at `0x004276e0`/`0x0042ec64`; on inspection those
> are two *unconnected* functions with an unverified value label — not the producer. Treat any such
> static "proof" of the producer with suspicion until it is confirmed at runtime.)

> **One correction up front.** Earlier drafts of this writeup called the faulting value
> "the compressed JPEG file size." That has since been **disproven by measurement**: the largest
> cover on the test device is ~130 KB, while the faulting value is 506,870 bytes (~½ MB). Its
> magnitude instead matches a *decoded* image buffer (e.g. a few hundred pixels square at 2–3
> bytes/pixel). The exact quantity is not proven, so below it is referred to as a "size-class value"
> rather than a file size.

A clarification on what is and is not proven. The intuitive first guess for a bug like this is a C
`union`: a single slot that overlaps the size and the pointer in the *same* memory, so that
forgetting to overwrite it leaves the number readable as a pointer. The on-device evidence rules that
out. The two fields sit at offsets `+4` and `+8` — two distinct slots, four bytes apart — whereas a
union would place them at the *same* offset. So the reuse is **temporal, not spatial**: slot `+8` is
seeded with the size-class value and is only overwritten by the real pointer on the success path
(the struct below models exactly this, with separate `+4` and `+8` fields and no union). The
equality of `result[+4]` and `result[+8]` on failure therefore shows the same value lands in both
fields and that the pointer is overwritten only on success; it does **not** by itself prove a union.
A union is simply the tidiest idiom that would produce the same bytes; two ordinary fields both
assigned the same value compile to the same thing.

```c
struct ImageDecodeResult {
    void *rawData;           // +0
    int   size;              // +4   a size-class value (magnitude ~ a decoded buffer; not proven)
    void *decodedDataPtr;    // +8   set on success; left holding `size` on failure
    int   width;             // +0xc
    int   format;            // +0x10
};

bool decode_cover(const char *path, ImageDecodeResult *result) {
    result->size           = result->width * result->height * bpp; // decoded-buffer byte count
    result->decodedDataPtr = (void *)result->size;  // +8 seeded with the size before decode

    void *buffer = malloc(result->size);            // fails under memory pressure
    if (buffer == NULL) {
        // BUG: returns without setting result->decodedDataPtr = NULL,
        // so +8 keeps the size-class value.
        return false;
    }
    result->decodedDataPtr = buffer; // +8 overwritten only on success
    return true;
}

void album_cover_parser(ListItem *item, const char *path) {
    ImageDecodeResult result;
    decode_cover(path, &result);              // return value not checked

    item->size      = result.size;            // +4
    item->coverPtr  = result.decodedDataPtr;  // +8  BUG: holds the size-class value on failure
    item->field_c   = result.width;           // +0xc
    item->field_10  = result.format;          // +0x10
}
```

The renderer later does `lw a0, 0x50(item->coverPtr)`; with `coverPtr` holding the non-pointer
value (`0x7bbf6 = 506,870`, below `0x00400000`), the load faults and the process takes SIGSEGV.
(In this model the failed `malloc` and the seeded `+8` are the *same* size value, which is why
`+4 == +8` on failure — consistent with the ~½ MB magnitude being a decoded-buffer size rather than
the compressed file.)

### A.1 — Why is a non-pointer value in the pointer field at all? (open question)

We can prove *what* happens (sections 4 and 6) but not *why the code was written to put a size
there in the first place*. This is genuinely the least certain part, and the original authors will
know the real answer from the source. The candidate explanations:

1. **Temporal reuse of one field (most consistent with the evidence).** The size at `+4` and the
   pointer at `+8` are at *different* offsets, so this is **not** a memory-overlapping `union`.
   Field `+8` is its own slot that is seeded with the size during loading (e.g. as a "bytes to
   read", "bytes remaining", or write-cursor scratch value) and is meant to be overwritten with the
   final decoded-buffer pointer at the end. The failure path returns before that overwrite. Under
   this reading the field is a working variable that does double duty over its lifetime.
2. **A generic / shared descriptor** reused across resource types (image, audio, and so on), where
   slot `+8` means different things per type and a shared init routine writes the size there.
3. **Organic drift / legacy code:** the field originally meant one thing, was repurposed, and was
   never refactored.

### A.2 — The "RAM saving" rationale does not hold up

If the reuse were ever defended as a memory optimisation, the numbers do not support it on this
device:

- It is **not even a space optimisation here.** Because `+4` (size) and `+8` (pointer) occupy
  separate offsets, the layout is the same whether or not `+8` is reused. The reuse is temporal,
  not spatial, so it saves **zero bytes** of struct size.
- Even in the hypothetical where `+4` and `+8` were merged into a real `union`, that saves **4
  bytes per descriptor** (a 32-bit pointer versus a 32-bit size). Across, say, a few thousand
  library rows that is single-digit kilobytes, on the order of **0.03% of the ~57 MB** of system
  RAM. The descriptors are largely transient anyway, so the realistic figure is far smaller.
- Field-overloading of this kind only pays off at massive scale (millions of elements: tagged
  pointers in VMs, NaN-boxing, flag bits in pointers). A handful of cover descriptors is the
  opposite case.

In short: the safer version (initialise `+8` to NULL up front, or keep size and pointer as
distinct, never-aliased fields) costs nothing measurable and removes the entire crash class. This
is the case where the better-engineered code is also the cheaper code.

---

## Appendix B — recommended source-level fixes

In priority order, for a proper upstream fix. (Item 1 names the producer generically because, as
section 4 shows, its exact location is behind a runtime virtual dispatch and not reachable from the
stripped binary — HiBy's engineers can find it from the source via the symbol clues in section 7.)

1. **In the cover-struct producer** (the method behind the virtual call at `*0x8ce0ec + 0x2c`,
   invoked via `0x004409e0`): on every allocation or decode failure, set the image-buffer field
   (`+8`) to NULL — or free and NULL the whole struct — before returning. This is the true root fix
   and makes every consumer safe.
2. **In `album_cover_parser` (`0x0042827c`):** validate `cover[+8]` (not just `cover != NULL`)
   before assigning it to the list item, and treat an invalid pointer as "no cover". This is exactly
   where the binary patch in this repo acts.
3. **Check every decode/allocation return explicitly.** Working-buffer allocations can and do fail
   on this hardware (~12 MB free). Note that the *sibling* allocator `0x0043d560` already does this
   correctly (frees and returns NULL) — the producing path should match it.
4. **Defensive:** the renderer already skips `coverPtr == 0`. Widen it to also skip pointers below
   the user-space text base `0x00400000`.
5. **Telemetry:** the in-process SIGSEGV/SIGBUS handlers currently mask faults like this from crash
   logging. Recording the faulting PC and registers (or a minidump) before terminating would let
   issues like this surface in QA instead of being silently swallowed.
