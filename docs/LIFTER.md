# The lifter

`tools/lifter.py` turns aarch64 machine code into C: one C function per
function, over an `Arm64Ctx`. Branches inside a function become `goto`, calls
become direct calls, and indirect branches go through a dispatch table keyed on
the recovered function starts.

```sh
python tools/lifter.py libengine.so --report
python tools/lifter.py libengine.so --out generated/ --shards 64
```

| Flag | What it does |
|---|---|
| `--report` | Print coverage instead of writing anything: what fraction of real instructions the emitters handle, and which forms are missing. |
| `--out DIR` | Write the generated C. One `lifted_NNN.c` per shard, plus `lifted.h` and `dispatch.c`. |
| `--shards N` | How many translation units to split across (default 64). One file of 12 MB of C is a compiler's worst case. |
| `--limit N` | Lift only the first N functions. For bisecting. |
| `--pc-notes` | Annotate each emitted line with its guest address. |

Several libraries can be given at once: an APK ships `libc++_shared.so` beside
the engine, and a call into that runtime lands in ARM code like any other, so it
has to be lifted too.

## Where functions begin and end

Function-boundary recovery is the hardest problem in static recompilation, and
NDK builds hand it to you: `.eh_frame` is complete because C++ exceptions need
it to be. That is read out of the binary rather than inferred.

It is not quite the whole answer, and the gap is the subject of two sections
below — coverage of *instructions* and coverage of *functions* move very
differently, and neither is the same as *discovering* every function that
exists.

## Instruction coverage is not function coverage

The two numbers move very differently, and only one of them decides whether a
build is possible. One unsupported instruction fails the whole function it sits
in, so function completeness lags instruction coverage badly and is the figure
worth watching:

| | instructions | functions |
|---|---|---|
| integer core only | 97.9% | 72.0% |
| + scalar FP, atomics, bitfield | 99.2% | 85.8% |
| + PC-relative literal loads | 99.2% | 92.9% |
| + NEON | 99.96% | 97.7% |
| whole engine, today | 99.93% | 98.6% |

The literal-load row is the clearest illustration. It was 1,389 instructions —
a tenth of a percent — but they are scattered roughly one per function, so
handling them moved function completeness seven points. Late in the tail, the
instruction column stops being informative entirely: what matters is how widely
a form is *spread*, not how often it occurs.

The second engine repeated the pattern with a different tail. Structured
load/store (`ld1`/`st1` through `ld4`/`st4`, and the replicating `ld1r`) and
fused multiply-accumulate were together about 5,000 instructions — under a tenth
of a percent — but they cluster in exactly the hand-vectorised routines an
engine leans on:

| | instructions | functions |
|---|---|---|
| shared emitters, before any of this | 99.86% | 99.0% |
| + structured memory, `fmla`, widening/narrowing, saturating, permutes | 99.99% | 99.7% |

## Function coverage is not function *discovery*

A third number sits behind both columns, and it is the one that was actually
holding the second engine back: how many functions the lifter is ever handed.

`.eh_frame` describes what can be unwound through, which is not the same set as
what can be called. A leaf that never throws is entitled to no entry at all. The
linker-synthesised PLT appears in none of it. And a function reached only
through a vtable is named by no call site either.

Each of those is recovered differently, and all three were needed:

- **The PLT** is a fixed 16 bytes per entry, so it is lifted mechanically.
- **Call targets nothing defines** are already known — they are exactly the
  addresses the lifter turns into trapping stubs. Lifting them instead, and
  repeating until no new ones appear, recovers the undescribed leaves.
- **Gaps** — runs of executable bytes no function covers — catch what remains,
  which is everything reached only as an address in data.
- **The symbol table.** An `STT_FUNC` symbol with a nonzero size is an exact
  start and extent, from the linker rather than from a heuristic. This is how
  hand-written assembly is found: it is entitled to no unwind entry, and most
  of it is reached through a function pointer rather than a direct `bl`, so
  call-site recovery misses it too.

The last one is worth its own line because of what it turned out to be hiding.
Any title with a network stack links OpenSSL, and OpenSSL's aarch64 core is
largely hand-written assembly: 63 functions on Tapped Out — `bn_mul_mont`,
the whole of P-256, `vpaes_*`, the SHA block functions, and `OPENSSL_cleanse`,
which OpenSSL calls to wipe a buffer on nearly every operation. All of them
were invisible. The program ran until the first TLS handshake and then trapped
on an indirect branch into the middle of the image.

Twenty-four of those did not lift, and that is fine: they are the ARMv8 crypto
extensions (`aese`, `aesmc`, `pmull`, `sha256h`), and OpenSSL only calls them
when `OPENSSL_armcap_P` says the CPU has them, which it reads from
`getauxval(AT_HWCAP)`. Answering that with zero keeps the stack on the NEON
and C paths, which do lift. **Do not "fix" `getauxval` to report real
hardware capabilities** — that sends TLS straight into a function that does
not exist.

The sources overlap heavily — the symbol table names most of what `.eh_frame`
already describes, 11,278 addresses of it here — and the emitter writes one C
function per entry it is given, so the union has to be taken on the start
address. Two entries for one address is two definitions of the same C function
and the link fails. `dedupe_starts()` does that, preferring `.eh_frame`'s
extent where the two disagree, and `tools/selftest.py` checks the invariant
without needing a build.

On the second engine that recovered 1,519 functions and took the stubs standing
in for undescribed call targets from hundreds to one. Nothing about it is
title-specific.
