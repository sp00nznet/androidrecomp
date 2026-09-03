# androidrecomp

> A toolkit for turning Android games' native engines into native desktop
> applications. Bring your own APK.

**Status: the shim layer is essentially closed.** On its first real target —
*The Simpsons: Tapped Out*'s 28 MB Scorpio engine — **770 of 776 imports
resolve**, and the window comes up with a live GL context. No lifter yet, so it
runs on arm64 hosts only. See [Milestones](#milestones).

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
| `runtime/window` | SDL2 window, GL context and event loop: the desktop stand-in for `GLSurfaceView`. |
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

And it caught a regression as it was introduced. Handling PC-relative literal
loads meant treating a `ldr` whose last operand is an immediate as a literal —
but a *post-indexed* load also ends with an immediate, so `ldr x0, [x9], #9`
started reading address 9. Every affected function had been counted as lifting
successfully. Locating the memory operand by search rather than by position
fixed it, and the sweep went from 90 failures back to none.

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

## Building and running the lifted program

```sh
python tools/lifter.py libengine.so --out generated --shards 64
cmake -S . -B build-lifted -DARC_LIFTED_DIR=generated
cmake --build build-lifted
```

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

On this engine, **1,294 of 1,527 constructors run**.

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
- [ ] **Lifter.** ARM64 → C, boundaries from `.eh_frame`, indirect branches via
      an address → function-pointer table. Over the whole 62,008-function
      engine: **99.93% of instructions lift, and 98.6% of functions lift
      completely.** What remains is a long tail of narrow NEON forms — lane
      widening and narrowing, `ld1`/`st1`, horizontal reductions — plus the
      `svc` sites, which need the shim rather than the lifter.

## Ports using this

- **tstorecomp** — *The Simpsons: Tapped Out*.
