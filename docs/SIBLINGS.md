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

## What flows back the other way

Everything below was found while working on Family Guy and is not specific to
it. All of it applies unchanged to tstorecomp, which should be regenerated on
top of it.

**The thread pointer has to be real.** `TPIDR_EL0` was answered with zero. Both
engines fault at address `0x28` during static initialisation because of it —
thirty-six times in one, six in the other. Bionic points that register at a
per-thread control block and compiled code indexes off it without checking, so
returning zero is not "no value", it is a null pointer with a small offset
added. An identical fault signature across two unrelated titles was the clue:
it cannot be a fact about either of them.

**`.eh_frame` is one of four sources of function boundaries, not the only one.**
It describes what can be unwound through. A leaf that never throws is entitled
to no entry, the linker-synthesised PLT appears in none of it, and a function
reached only through a vtable is named by no call site either. Recovering call
targets that nothing defines, and then sweeping the gaps between everything
known, found 1,519 more functions in one engine and took the trapping stubs from
hundreds to one. This is the single highest-value change in the set, and the
older port has never had it.

**The instruction tail is narrower than it looks, and shared.** Structured
load/store, fused multiply-accumulate, the widening and narrowing forms, the
saturating family, permutes and table lookup were about 5,000 instructions in
one engine — under a tenth of a percent — but they cluster in hand-vectorised
routines, so covering them moved function completeness from 99.0% to 99.7%.
The same emitters serve any target.

**Two disassembler details cost real bugs**, and would cost them again in any
port that adds structured memory support independently. The post-index increment
of `ldN`/`stN` is absent from the operand list, because the instruction encodes
it as the size of the transfer; taking it from the generic write-back path
yields a silent zero. And the lane index of a register list is reported on the
*last* register only — reading it from the first gives -1, which is not an error
but a different instruction.

**A vendored toolkit is not the toolkit.** Each port carries `androidrecomp` as
a submodule, so edits to a standalone clone do not reach a port's build. Two
separate diagnoses in one session were confounded by this: a fix appeared to
have no effect, and a rebuild reported nothing to do, because the port was
building a pinned older commit. Change the kit, push it, then move the port's
submodule — in that order, every time.

## Bringing a title up: what the second port had to learn

Everything here was found driving Family Guy from static initialisation to a
running renderer. None of it is about Family Guy, and tstorecomp has had none
of it -- its six remaining constructor failures are all null dereferences,
which is the shape every one of these had before it was understood.

**That last sentence was a guess, and it was wrong.** tstorecomp was rebuilt on
all of the above -- JNI_OnLoad, the corrected slot indices, the enlarged
registration table, the asset manager, stack arguments, setjmp -- and the six
failures came back identical: same constructors, same addresses, same null
offsets. Nothing above touched them. The reasoning was that two engines failing
the same way probably fail for the same reason, which had been true of the
thread pointer and was not true here.

What they actually were is worth more than the guess. Three of them faulted
writing to address 0x16, and 0x16 was simply what x2 held; the frame trail
named `sincosf`. Its first argument is a float, so it arrives in v0 -- and the
native thunk carries the integer registers only. Bound the ordinary way, the
host function takes the guest's two output pointers as its first and second
arguments and writes a result through whatever was in the third.

The thunk had said so all along: *it does NOT carry floating-point arguments,
which live in v0-v7 ... generate those from the import list when a title
actually needs one.* A documented limitation is not a harmless one. It sat
unexercised through one whole port and then presented as memory corruption in
the next, three constructors deep, with nothing in the symptom pointing at the
calling convention.

**So: check the import list against the thunk's reach before blaming the code
it fails in.** Any imported function taking a float, a double, or a struct by
value needs the context, exactly as a variadic one does.

**A library expects JNI_OnLoad.** The Java runtime calls it after loading a
library and running its static constructors, handing over the JavaVM. A library
caches that pointer and reaches every later thread's environment through it, so
skipping the call leaves a null that surfaces much later, inside whatever first
tries to call back into Java. Both engines export it. The host does this now,
so a port does not have to remember to.

**Startup is a sequence, not an entry point.** cocos2d-x builds its Application
inside the first native method Android invokes, and the renderer entry point
calls getInstance on it. Calling the second without the first finds a null
singleton. Which methods, and in what order, is a property of the title and
belongs in its contract.

**The table of context-taking natives has to fit a whole JNI table.** It held
64 entries; a JNI environment has 233. Everything past the sixty-fourth was
dropped in silence, so the guest branched to a real stub address the dispatcher
had no record of, and the report blamed the branch. Both registration tables
now say when they are full, because the symptom of overflow points anywhere but
at the cause.

**The native thunk carries stack arguments now.** It passed the eight integer
registers AArch64 uses and nothing else, which is enough for almost everything
and not enough for glTexImage2D -- nine arguments, the ninth being the pixel
data. Nothing reported a missing argument: the call was made and the driver
read an address nobody had passed.

**Paths handed to the guest must be absolute and use forward slashes.** The
guest is Android code: it splits on the separator it knows and has no notion of
a working directory of ours. A relative Windows path arrives as one long
filename containing none, which is not a wrong directory but no directory.

**And the guest may expect to be running in its own bundle.** Some files are
opened by bare name, with no directory at all -- on Android the app is launched
that way and never has to say so. A relative open cannot be corrected after the
fact, because by the time the name arrives there is nothing left in it to say
which directory was meant.

**Read the engine's own log before reasoning about it.** Every one of the last
several blockers announced itself in plain words -- a missing asset manager, a
JSON document that would not parse, a file that was not found, a random device
that could not be opened -- while the visible symptom was a null dereference
somewhere unrelated. The log is on stderr from the first run; it costs nothing
and it was repeatedly ahead of the analysis.
