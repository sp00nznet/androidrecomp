# What the sibling projects owe each other

Three repositories now share one design: a platform kit, and per-title ports
that vendor it.

| kit | ports | target |
|---|---|---|
| **androidrecomp** | tstorecomp, fgrecomp | arm64 Android `.so` |
| **iparecomp** | canabaltrecomp | 32-bit ARM Mach-O |

They will drift unless what each learns is written down where the other can
find it. This is that list.

## androidrecomp → iparecomp

iparecomp's emitter is its next milestone. Everything here was learned *after*
androidrecomp's lifter existed, at a cost, and is cheaper to build in from the
start than to retrofit.

**Build the oracle before the emitter.** Unicorn covers 32-bit ARM as well as
arm64, and it is an independent implementation, which is the property that
matters — a misreading invented in the emitters is not mirrored in it. Two
harnesses, not one:

- *Per instruction*, over forms harvested from a real binary. This found that
  immediates carry their own shift (`add w9, w20, #2, lsl #12` is 8192, not 2),
  and that an extended-register operand carries an extend *and* a shift, in that
  order — widen first, then shift, or everything crossing the 32-bit boundary is
  silently lost.
- *Per whole function*, which covers the control flow the first one cannot. This
  found a load pair whose base register was also its first destination reading
  its second element through the value the first had just loaded.

That second bug is the argument for having both. A "form" keyed on mnemonic and
operand shapes does not record whether the base is also a destination, so the
instruction harness could only ever have found it by luck.

**Watch function completeness, not instruction coverage.** They move very
differently and only one decides whether a build is possible, because a single
unsupported instruction fails the whole function it sits in. PC-relative literal
loads were a tenth of a percent of instructions and *seven points* of function
completeness, because they are spread about one per function. Late in the tail,
how widely a form is spread matters more than how often it occurs.

**The corner cases where C and the hardware disagree.** Each produces a
plausible wrong number rather than a crash:

- An invalid operation (`0/0`, `inf - inf`, `0 * inf`) yields a NaN whose sign
  bit x86 sets and ARM clears. This affects all four basic operations, not just
  `sqrt`.
- ARM's `fmin`/`fmax` propagate NaN; C's `fmin`/`fmax` deliberately do not. Only
  `fminnm`/`fmaxnm` match C.
- Float-to-integer is saturating on ARM and *undefined behaviour* in C once the
  value does not fit, so it cannot be written as a cast at all.

**Harness hygiene, each learned by losing a run:**

- Scratch memory needs guard pages. Carved out of the interpreter's heap, an
  overrun is heap corruption, which kills the run and reports nothing.
- Pointers seeded into scratch must be forward-only. Self-referential scratch
  lets a function walk a pointer chain instead of faulting — but pointers that
  can go backwards make cycles, and a function walking a cyclic list never
  returns.
- Restore the image from a pristine copy before every case. Lifted functions
  write to globals, so without it each result depends on what ran before, and
  changing the lifter silently reshuffles which cases pass.

**Make a fault self-describing.** A fault in lifted code names an address in the
data it touched and never the code that touched it; the host call stack is tens
of thousands of identically shaped C functions. Three things fixed that, all
platform-neutral:

- Ask the OS what an address is. Committed, reserved or unallocated, with its
  protection — the difference between a wild pointer and a real region touched
  the wrong way.
- Record the last calls *out* to the host, and their arguments. This is what
  finally located a failure that five rounds of inference had not: an allocation
  of eighteen exabytes, from a handle truncated to 32 bits.
- Record which guest functions were entered, as a ring rather than a stack —
  nothing to pop, so no return path can be missed.

**One layering rule, learned twice from opposite directions.** Anything the shim
calls must be *defined* in the library; anything generated must *plug in*. The
library owns `arc_dispatch` and a lifted program installs its own through
`arc_set_dispatch`, because the shim itself has to dispatch — a guest thread's
entry point is a guest address, not a host function.

**"Resolved" is not "is a host function".** An import satisfied by another guest
image has a perfectly real address and looks resolved like any other. It is
guest machine code. Calling it natively faults on *execute*, inside memory that
is definitely mapped — which is exactly as confusing as it sounds until the
fault reports which of read, write or execute it was.

## iparecomp → androidrecomp

**Triage should be able to stop.** `ipa_probe.py` checks FairPlay encryption
first and refuses to print anything else, because nothing below that line is
meaningful when the text section is ciphertext. `apk_probe.py` has no notion of
a disqualifying finding — it reports numbers whatever it finds. It should gate
on at least:

- *No arm64 slice.* An `armeabi-v7a`-only APK needs an ARM32 lifter, not a
  shim. This is not rare: Google's 64-bit mandate only ever applied to apps
  still shipping updates, so the delisted catalogue is frozen at 32-bit. Say so
  and stop.
- *Low `.eh_frame` coverage.* Function-boundary recovery is the hardest problem
  in static recompilation and unwind tables are what make it free. A stripped
  binary without them is a different and much larger project.

**Keep the contract extractors symmetric.** `objc_dump.py` and
`dex_contract.py` are the same tool for different platforms: recover what the
host contract *expects* from metadata the platform already writes down, rather
than guessing. `objc_dump.py` has a `--contract` mode that emits a contract file
directly; `dex_contract.py` should grow one.

That symmetry is worth defending, because on both platforms the same mistake is
available: knowing an entry point's *name* and assuming that is enough to call
it. It is not. On Android, `init` turned out to be `init(BGAndroidInfo)`, and
the object it takes has eighteen fields the engine reads before doing anything
else.

## What fgrecomp proved, that changes both

**Ask whether the engine is already known.** Family Guy's engine is a fork of
cocos2d-x 4.0, and the binary says so in plain text. That single fact converts
the host contract from something reverse-engineered into something *read*: every
entry point has public source on the other side of it, and the engine ships an
official desktop backend that is a reference implementation of the behaviour the
host has to reproduce.

Neither probe looks for this, and both should. Scanning for engine fingerprints
in a binary's strings costs nothing and is plausibly the highest-leverage
question in the whole triage.

**Choose targets by triage rather than by preference.** fgrecomp's README opens
with a comparison table against tstorecomp, and it is not close: 100% `.eh_frame`
coverage against 98.8%, two undisassembled bytes against 24,916, no shipped
`libc++_shared.so`, no proprietary middleware, no syscall sites, no pointer
authentication. Both projects were started on instinct; only one was measured
first.

**A contract can cover more than one title.** One Griffin host contract covers
three games. That is an argument for putting engine-level contracts somewhere
they can be shared, rather than in a single port.
