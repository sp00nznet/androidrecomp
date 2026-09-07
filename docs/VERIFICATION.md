# Verifying a lifter

Three harnesses, none of which needs arm64 hardware.

| Harness | What it proves |
|---|---|
| `tools/selftest.py` | The loader works, against a synthetic library. No APK, no NDK, no arm64. |
| `tools/lift_verify.py` | Each *instruction* lifts to the right arithmetic, against Unicorn. |
| `tools/lift_verify_fn.py` | Each *function* lifts to the right control flow, against Unicorn, over the real image. |

## The loader self-check

No game may live in this repository, so `selftest.py` hand-assembles an ELF that
exports a JNI-shaped host contract and exercises all four relocation types a
real NDK library uses, then loads it with `arc_host` and checks the result. It
runs anywhere.

```sh
python tools/selftest.py
```

## Verifying a lifter with no arm64 hardware

A lifter is normally validated by running the lifted code on the real machine
and diffing the register state. Without arm64 hardware that is not available —
so the oracle is [Unicorn](https://www.unicorn-engine.org/), a QEMU-derived
arm64 emulator that runs on x86. What matters is that it is an *independent*
implementation: a misreading we invent in the emitters is not mirrored in it.

`lift_verify.py` harvests real instructions from a real library rather than
synthesising them, groups them by operand shape, and feeds the same randomised
register state, flags and memory to both the compiled lifted C and Unicorn,
then compares registers, flags and memory.

It paid for itself on the first run, with three bugs that reading the code would
not have found:

- Immediates carry their own shift. `add w9, w20, #2, lsl #12` means 8192, not
  2 — off by exactly 8190.
- Extended-register operands carry an extend *and* a shift, not one or the
  other, so `add x8, x8, w25, sxtw #3` was dropping the sign extension.
- And the order of those two matters: the source widens to 64 bits first, then
  shifts. Shifting in the source width silently discards everything that
  crosses the 32-bit boundary.

Floating point produced two more of the same kind, where C and the architecture
simply disagree:

- `fsqrt` of a negative gives the *default* NaN, sign bit clear. C's `sqrtf`
  returns a negative NaN — one bit different.
- ARM's `fmin`/`fmax` **propagate** NaN. C's `fminf`/`fmaxf` deliberately do
  not; only ARM's `fminnm`/`fmaxnm` match them. Using the C function for the
  propagating form returns a number where the hardware returns NaN.
- The same sign difference reaches every one of `fadd`, `fsub`, `fmul` and
  `fdiv`. When an operation is *invalid* -- `0/0`, `inf - inf`, `0 * inf` --
  x86 produces a NaN with the sign bit set and this architecture's default NaN
  has it clear. A propagated input NaN follows a third rule again: it keeps its
  payload and is merely quieted. Found by the whole-function sweep, not by
  reading.

And it caught a regression as it was introduced. Handling PC-relative literal
loads meant treating a `ldr` whose last operand is an immediate as a literal —
but a *post-indexed* load also ends with an immediate, so `ldr x0, [x9], #9`
started reading address 9. Every affected function had been counted as lifting
successfully. Locating the memory operand by search rather than by position
fixed it, and the sweep went from 90 failures back to none.

The structured load/store work produced three more, two of them about the
disassembler rather than the architecture:

- **The post-index increment is not in the operand list.** These encode it as
  "however much was transferred" rather than as an immediate, so capstone
  reports the instruction as writing back and leaves no operand saying by how
  much. Taking it from the generic write-back path produced a silent zero, and
  every loop built on `ld1 {v0.4s}, [x0], #16` read the same 16 bytes forever.
- **The lane index of a register list belongs to the last register.** In
  `st3 {v16.b, v17.b, v18.b}[1]` only `v18` reports lane 1; the others report
  none. Reading it from the first gave -1, which is not an error — it is the
  whole-register form, a different instruction that stores 48 bytes instead of
  three.
- `uabd` and `uaba` differ only in the final letter, and the test for the
  accumulating spelling looked at the second. Plain `uabd` accumulated into its
  destination.

All of these produce plausible wrong numbers rather than crashes, which is what
makes an independent oracle worth more than careful reading.
