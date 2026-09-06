# androidrecomp

> A toolkit for turning Android games' native engines into native desktop
> applications. Bring your own APK.

**Status: the shim layer and the lifter are both essentially closed**, on two
unrelated engines. *The Simpsons: Tapped Out*'s 28 MB Scorpio engine resolves
**770 of 776 imports**, brings up a window with a live GL context, and runs
1,521 of its 1,527 static constructors. *Family Guy: The Quest for Stuff*'s
cocos2d-x engine lifted at **99.0% of functions with no title-specific work at
all** — the first evidence that the kit generalises — and now runs **all 1,202 of
its constructors** at 99.8% of functions and 100.00% of instructions. See
[Milestones](#milestones).

---

## What this is

A great many Android games are a thin Java shell wrapped around a large native
`.so`. The Java side owns a window, a GL context and a touch handler and calls
into the engine through a handful of JNI methods; everything that matters —
renderer, simulation, game logic — is ARM64 machine code in the library.

That shape is what makes those games portable. Replace the Java shell with a
desktop host, satisfy the library's POSIX/OpenGL import surface, and lift the
ARM64 code to C for machines that are not ARM. The result is an ordinary native
executable — no emulator, no Android runtime, no APK at runtime.

Same philosophy as [N64Recomp](https://github.com/N64Recomp/N64Recomp),
[UnleashedRecomp](https://github.com/hedge-dev/UnleashedRecomp) and
[ps3recomp](https://github.com/sp00nznet/ps3recomp), aimed at Android instead of
a console.

**This repository is deliberately game-agnostic.** A port supplies its own JNI
bridge and host contract and links the library here. Nothing title-specific
belongs in this repo — that separation is the whole point, and it is much
cheaper to keep than to retrofit.

## Legal / content policy

Tools only. No game code, no game assets, no extracted art, no save data, no
publisher binaries — `.gitignore` blocks all of it, deliberately. You supply
your own legally obtained APK; everything here operates on a file you already
have. Licensed MIT; contributions must be your own work.

## What you get

| Piece | What it does |
|---|---|
| `runtime/elf_image` | Maps an arm64 Android `.so`, applies its relocations, binds imports through a resolver, sets page protections. Loads a library's APK-shipped dependencies too, so they can satisfy its imports. No dependencies. |
| `runtime/shim` | Resolves imports in layers: explicit implementations, ABI-identical name aliases, then the host C runtime looked up by name. Most of libc costs no code per symbol. |
| `runtime/shim_pthread` | Threads, semaphores and TLS keys on `std::thread` and the C++ primitives. |
| `runtime/shim_posix` | The locale `*_l` family, time, the stdio entry points MSVC hides inline, wide-character and BSD string helpers. |
| `runtime/shim_gl` | GL by name through the live driver — desktop GL exports most GLES2 entry points under identical names, so this costs no code per symbol either. |
| `runtime/shim_file` | File I/O, directories and `mmap` at Bionic's struct layouts and flag values, which are *not* the host's. |
| `runtime/shim_sys` | Sockets, `dlopen`/`dlsym`/`dl_iterate_phdr` over the loaded images, process and system. |
| `runtime/shim_asset` | The Android asset manager over an ordinary directory. An APK carries a title's own files under `assets/` and the engine reads them through this rather than through `open`, so without it a game loads nothing. There is nothing to emulate: the APK is a zip and the host has a filesystem. |
| `runtime/jni_env` | The `JNIEnv` and the `JavaVM` the engine calls back through: field and method lookup, string and array access, the invocation interface. Answers by name, and reports what it was asked for and could not answer. |
| `runtime/window` | SDL2 window, GL context and event loop: the desktop stand-in for `GLSurfaceView`. The context is made current on whichever thread runs the guest, because a GL context belongs to one thread at a time and the guest gets one of its own. |
| `tools/apk_probe.py` | Feasibility triage for a new title: imports, function count from `.eh_frame`, instruction histogram, and the constructs a lifter must special-case. |
| `tools/arc_host.cpp` | Loads a library and prints the outstanding-import work list. With no `--contract`, lists every `Java_*` export — how you discover a title's host contract. |
| `runtime/arm64_context.h` | Guest CPU state and the operations lifted code emits. No address translation: guest pointers *are* host pointers. |
| `tools/lifter.py` | aarch64 → C, one C function per `.eh_frame` function. `--report` says what fraction of real instructions the emitters cover. |
| `tools/lift_verify.py` | Differential-tests the lifter against Unicorn on real harvested instructions — an independent oracle that needs no arm64 hardware. |
| `tools/lift_verify_fn.py` | The same, for whole functions: builds the lifted program and runs it against the emulator with the image mapped at the same address on both sides. |
| `tools/arc_boot.cpp` | Runs the lifted program's static constructors, then an entry point. Recovers from traps and faults so one run enumerates every failure. |

## Building

CMake 3.20+ and any C++17 compiler. zlib and SDL2 are optional; without them
those imports simply stay on the work list.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

python tools/selftest.py                    # loader self-check, no APK needed
./build/arc_host path/to/libengine.so       # what does it still need?
./build/arc_host --window path/to/libengine.so
```

On Windows add `-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake`
so CMake finds zlib and SDL2. A toolchain file only takes effect on a fresh
cache, so delete `build/` if you add it later.

Triage a new title before committing to it:

```sh
pip install capstone pyelftools
python tools/apk_probe.py game.apk --out triage.md
```

## Method

Point `apk_probe.py` at an APK. The numbers that decide whether a port is weeks
or years:

- **Functions recovered from `.eh_frame`.** Function-boundary recovery is the
  hardest problem in static recompilation, and NDK builds ship complete unwind
  tables — so it is usually free. Low coverage here is the main red flag.
- **Undefined symbol count.** This is the shim surface. A few hundred standard
  POSIX/GL symbols is routine; thousands of exotic ones is not.
- **Indirect branches.** C++ vtable dispatch, resolved against the recovered
  function starts.
- **TLS, exotic relocations, `svc` sites.** Small counts mean a small loader.

Then `arc_host` turns the remaining unknowns into a work list that shrinks.

Three rules earn their keep at the shim boundary:

**If the APK ships it, load it.** Any `DT_NEEDED` entry sitting next to the
engine is loaded as its own image and used to satisfy the engine's imports;
everything else is an Android system library and falls to the shim. This is what
answers `libc++_shared.so`'s NDK-mangled (`_ZNSt6__ndk1...`) symbols, which no
host STL can provide. The exception worth knowing: a shipped `libopenal.so`
resolves plenty but drags in `libOpenSLES` imports, because its audio backend is
Android's — link native openal-soft instead.

**Fit inside the guest's storage; do not match its layout.** An engine allocates
`pthread_mutex_t` inline in its own structures, sized by Bionic's headers when
it was compiled. Guessing those sizes wrong is silent corruption, not a crash.
We never guess: every pthread call routes through the shim, so the bytes are
opaque to the engine, and each object holds nothing but a 32-bit id naming a
registry entry. Bionic's smallest such type is `pthread_once_t` at four bytes,
so a `uint32_t` fits them all, with no NDK headers needed to prove it.

**A smaller host struct written into a larger guest allocation is safe; the
reverse is not.** Bionic's `struct tm` carries two fields more than the
Microsoft CRT's, so filling one from the host leaves the leading fields correct
and the tail untouched. It runs the other way too: Bionic's `struct stat` and
`struct dirent` share no layout with the host's, so those are filled field by
field at Bionic's offsets instead of letting the host write its own shape.

The corollary is that the best answer is often to need neither. `__sF` is the
array behind `stdin`/`stdout`/`stderr`, and the engine indexes it with its own
baked-in `sizeof(FILE)` — a stride we cannot know. So the shim reserves a region
and treats *any* pointer inside it as a standard stream: the base is stdin,
anything else stderr. Diagnostic output does not care, and the stride never has
to be guessed.

The same discipline governs aliases: `mkdir(path, mode)` and the Microsoft CRT's
`_mkdir(path)` are not the same function, and aliasing them would compile, link,
run and corrupt the stack. Nor are Bionic's open flags the host's — `O_CREAT` is
0100 against 0x100 — and `struct addrinfo` orders `ai_addr` and `ai_canonname`
the opposite way from Winsock's. Each of those fails silently, not loudly.

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

On the second engine that recovered 1,519 functions and took the stubs standing
in for undescribed call targets from hundreds to one. Nothing about it is
title-specific.

## Building and running the lifted program

```sh
python tools/lifter.py libengine.so libc++_shared.so --out generated --shards 64
cmake -S . -B build-lifted -DARC_LIFTED_DIR=generated
cmake --build build-lifted
```

A program is not one library. An engine calls into the C++ runtime the APK
ships beside it, and those calls land in ARM code like any other, so every
image the guest executes has to be lifted into the same program. The dispatch
table spans them, keyed on which image an address falls inside; function names
carry the image index because offsets overlap between images; and each lifted
function refers to its own image's load address, which is fixed when the C is
generated rather than carried at run time.

For this engine that is 430 MB of C across 66 translation units, which compiles
in about 75 seconds. Every recovered function becomes a C function; the 1.4%
that do not lift become stubs that trap, so the program links and an incomplete
lift surfaces when that path is taken rather than at build time. Indirect
branches go through a sorted address → function-pointer table, and a miss traps
the same way.

Then check it against the oracle, whole functions at a time:

```sh
python tools/lift_verify_fn.py libengine.so --generated generated --count 250
```

This is where control flow gets tested, which the single-instruction harness
deliberately cannot cover. The lifted program runs against the real image
loaded at a real host address, and the emulator is given its own copy at the
same numeric address — along with the same stack and argument memory — so a
load of a global or a pointer walk reads identical bytes on both sides.

## Booting it

```sh
cmake -S . -B build-lifted -DARC_LIFTED_DIR=generated
cmake --build build-lifted --target arc_boot
./build-lifted/arc_boot libengine.so
```

`arc_boot` runs the lifted program's static constructors and then, optionally,
a named entry point. Constructors are the right first thing to run: they
allocate, take locks and build tables, touching a large part of the shim
without needing a window, a JNI environment or a server. Failures are recovered
rather than fatal — a boot that dies on the first bad constructor tells you one
thing per run, one that keeps going tells you the shape of what is left.

On this engine, **1,521 of 1,527 constructors run**, and `init` then executes
far enough to print the engine's own startup banner through the logging shim
and make 96 JNI calls before it stops. On the second engine — a different
vendor, a different renderer, no title-specific work — **all 1,202 run**.

Constructors are also a good measure precisely because a whole boot is not one:
the failures come back as a histogram, and a histogram is diagnosable. Thirty-six
of the second engine's constructors failed at address `0x28`, one address, one
signature — which is a single cause, not thirty-six bugs. It was `TPIDR_EL0`,
the thread pointer, which the shim answered with zero: Bionic points it at a
per-thread block and compiled code indexes off it without checking, so zero is
not "no value" but a null pointer with a small offset added.

Two things had to exist first, and both are general.

**The PLT has to be lifted.** `.eh_frame` describes the functions a compiler
emitted; the PLT is synthesised by the linker and appears in none of it. But
every call to an imported function goes through it — and a C++ static
constructor registers its destructor through `__cxa_atexit` before doing
anything else, so *every* constructor failed on the same missing stub. The
entries are a fixed 16 bytes each, so lifting them is mechanical, and it took
the count of unreachable branch targets from 6,080 to 12.

**Calls out to the host need a bridge.** The guest reaches an import exactly as
it reaches a virtual method: it loads a GOT slot and branches to it. That
address is a host function the shim supplied, so the dispatch table will never
contain it. Registering the resolved imports lets an indirect branch tell the
two apart, and a generic thunk marshals the integer half of the calling
convention across. Floating-point arguments live in `v0`-`v7` and are not
carried yet; that needs per-signature thunks generated from the import list.

**"Resolved" is not the same as "a host function".** An import satisfied by
another *guest* image — the APK's own `libc++_shared.so`, say — has a perfectly
real address, so it looks resolved like any other. It is ARM code. Handing it to
the native thunk calls it as though it were x86, which faults on *execute*
rather than on read or write, at an address inside an image that is definitely
mapped. Reporting which of the three kinds of access faulted is what makes that
diagnosable at all; without it the symptom is an impossible-looking fault in
memory you allocated yourself.

The lesson generalises: a guest image's imports partition into ones the host
satisfies and ones another guest image satisfies, and only the first kind may
be called natively. The second kind belongs to the dispatcher, and traps until
that image is lifted too.

### A JNIEnv with nothing behind it

A JNI entry point takes a `JNIEnv*` and dereferences it immediately, because in
JNI an environment *is* a pointer to a pointer to a table of function pointers.
That is why the first call to `init` faulted reading address zero.

`runtime/jni_env.cpp` supplies the shape without the substance: 256 distinct
stub slots, each registered with the native bridge so an indirect branch into
the table is recognised as a call out to the host. Every slot returns zero and
records that it was called.

Writing named implementations for all 233 real JNI functions before knowing
which are needed would be a great deal of speculative work. Running it answers
the question instead — this engine's `init` touches nine slots, and those are
the ones worth implementing.

Where it stops is the natural consequence: a stub returning zero hands the
engine a null class or method handle, and it dereferences one. Returning
distinguishable non-null handles is the next thing to try.

### Two mnemonics were 48% of a library

`libc++_shared.so` initially lifted at 47.7% of functions against libscorpio's
98.6%, and the whole difference was `paciasp` and `autiasp` — 2,700 of the
2,750 instructions that failed. It was built with `-mbranch-protection`, so
every non-leaf function signs the return address on entry and authenticates it
on exit.

Both are identity operations for a lifted program. Signing defends a return
address held in memory an attacker might corrupt; ours lives in the context,
there is no key, and a lifted `ret` returns from a C function rather than
branching through `x30`. Treating the pair as no-ops preserves exactly what it
guarantees on hardware — that `x30` is unchanged from entry to exit — and took
the library to 99.7%.

## Two execution paths, one host

The host program is needed either way, so it comes first.

**Native arm64.** On Apple Silicon, Windows-on-ARM and arm64 Linux the engine's
instructions already run; what is missing is Bionic and Android. Once the shim
is complete, the mapped image is callable directly — a playable port with no
lifting at all, and the reference a lifted build gets diffed against.

**Lifted x86-64.** The same host linked against generated C instead of a mapped
ELF.

## Milestones

- [x] **Loader.** Map, relocate, bind, protect; load APK-shipped dependencies.
- [x] **Shim.** libc, libc++, threads, locale, time, stdio, zlib, GL.
- [x] **Window.** SDL2 window, GL context, event loop.
- [x] **File I/O and memory.** POSIX file I/O, directories and `mmap`, written
      at Bionic's struct layouts rather than forwarded to the host's.
- [x] **Sockets and dynamic linking.** Including `dl_iterate_phdr` over the
      loaded images, which is how guest C++ exceptions find their `.eh_frame`.
- [ ] **JNI bridge.** A `JNIEnv` the engine can call back through, and input
      translation. Per-title glue lives in the port; the reusable parts land here.
- [ ] **Audio.** openal-soft in place of a shipped `libopenal.so`. A shipped
      OpenAL resolves plenty but pulls in `libOpenSLES` — its backend is
      Android's, and it is the one library worth replacing rather than loading.
- [x] **Lifter.** ARM64 → C. Boundaries from `.eh_frame`, the PLT, call sites
      and the gaps between them; indirect branches via an address →
      function-pointer table. On the second engine, **100.00% of instructions
      and 99.8% of functions lift completely**, and 750 of 750 differential
      cases across 68 operand forms agree with the oracle. What remains is a
      long tail of narrow forms — horizontal reductions, a few scalar FP
      spellings — plus the `svc` sites, which need the shim rather than the
      lifter.

## Ports using this

- **tstorecomp** — *The Simpsons: Tapped Out*.
- **fgrecomp** — *Family Guy: The Quest for Stuff*. The kit's first
  second target, and the one that showed how much of it was general: 99.0% of
  functions lifted on the first run with no changes to the toolkit at all.
