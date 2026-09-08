# androidrecomp

> A toolkit for turning Android games' native engines into native desktop
> applications. Bring your own APK.

**Status: a title renders.** *The Simpsons: Tapped Out*'s 28 MB Scorpio engine
resolves **770 of 776 imports**, runs **all 1,527** of its static constructors
with no faults, boots its game state machine, reads its own asset packs, and
renders and presents frames through a desktop GL context while forwarding mouse
input as touch — its own splash screen, drawn by lifted ARM64 code with no
emulator and no Android runtime. There is a screenshot in
[tstorecomp](https://github.com/sp00nznet/tstorecomp), which is where anything
title-specific belongs.

*Family Guy: The Quest for Stuff*'s cocos2d-x engine lifted at **99.0% of
functions with no title-specific work at all** — the first evidence that the kit
generalises — and is now lifted whole: **100% of its functions and 100% of its
instructions**. It runs all 1,202 of its static constructors, completes all
three of the JNI entry points Android calls on startup, and reaches **the game's
own loading screen**. See [Milestones](#milestones).

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

| Piece | What it does | More |
|---|---|---|
| `runtime/elf_image` | Maps an arm64 Android `.so`, relocates it, binds its imports through a resolver, loads the dependencies the APK ships beside it. No dependencies of its own. | [LOADER](docs/LOADER.md) |
| `runtime/shim` | Resolves imports in three layers: explicit implementations, ABI-identical name aliases, then the host C runtime by name. Most of libc costs no code per symbol. | [SHIM](docs/SHIM.md) |
| `runtime/shim_file` | File I/O, directories and `mmap` at Bionic's struct layouts and flag values, which are *not* the host's. | [SHIM](docs/SHIM.md) |
| `runtime/shim_pthread` | Threads, semaphores and TLS keys, over storage whose layout we never inspect and only have to fit inside. | [SHIM](docs/SHIM.md) |
| `runtime/shim_posix` | The locale `*_l` family, time, the stdio entry points MSVC hides inline, wide-character and BSD string helpers. | [SHIM](docs/SHIM.md) |
| `runtime/shim_sys` | Sockets with the two fields Winsock reorders, plus `dlopen`/`dlsym`/`dl_iterate_phdr` over the loaded images. | [SHIM](docs/SHIM.md) |
| `runtime/shim_varargs` | Formatting for functions taking the guest's own `va_list`, which is a 32-byte structure and not a pointer. | [SHIM](docs/SHIM.md) |
| `runtime/shim_zlib` | zlib across a `z_stream` that is 112 bytes in the guest and 88 here, because `uLong` differs. | [SHIM](docs/SHIM.md) |
| `runtime/shim_asset` | The Android asset manager over an ordinary directory. The APK is a zip and the host has a filesystem; there is nothing to emulate. | [SHIM](docs/SHIM.md) |
| `runtime/shim_gl` | GL by name through the live driver, plus the three places where the *language* or the *calling convention* differs and a wrong answer is a black screen. | [GRAPHICS](docs/GRAPHICS.md) |
| `runtime/window` | SDL2 window, GL context and event loop: the desktop stand-in for `GLSurfaceView`. | [GRAPHICS](docs/GRAPHICS.md) |
| `runtime/jni_env` | The `JNIEnv` and `JavaVM` the engine calls back through. Answers by name, and reports what it was asked for and could not answer. | [JNI](docs/JNI.md) |
| `runtime/arm64_context.h` | Guest CPU state and the operations lifted code emits. No address translation: guest pointers *are* host pointers. | [RUNTIME](docs/RUNTIME.md) |
| `runtime/arm64_runtime.c` | Indirect dispatch, calls out to the host and back into the guest, traps, and what a fault reports. | [RUNTIME](docs/RUNTIME.md) |
| `tools/lifter.py` | aarch64 → C, one C function per `.eh_frame` function. `--report` says what fraction of real instructions the emitters cover. | [LIFTER](docs/LIFTER.md) |
| `tools/lift_verify.py` | Differential-tests each instruction against Unicorn — an independent oracle that needs no arm64 hardware. | [VERIFICATION](docs/VERIFICATION.md) |
| `tools/lift_verify_fn.py` | The same for whole functions, against the real image mapped at the same address on both sides. | [VERIFICATION](docs/VERIFICATION.md) |
| `tools/selftest.py` | Loads a hand-assembled synthetic library. No APK, no NDK, no arm64. | [VERIFICATION](docs/VERIFICATION.md) |
| `tools/apk_probe.py` | Feasibility triage for a new title: imports, function count, instruction histogram, the constructs a lifter must special-case. | [TRIAGE](docs/TRIAGE.md) |
| `tools/arc_host.cpp` | Loads a library and prints the outstanding-import work list. With no `--contract`, lists every `Java_*` export. | [TRIAGE](docs/TRIAGE.md) |
| `tools/dex_contract.py` | Recovers JNI entry-point *signatures* from the APK's dex, which the exports alone do not give you. | [TRIAGE](docs/TRIAGE.md) |
| `tools/arc_boot.cpp` | Runs a lifted program's constructors, then entry points, then a frame loop. Recovers from traps and faults so one run enumerates every failure. | [BOOTING](docs/BOOTING.md) |

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

On Windows the Visual Studio generator is multi-config, so `CMAKE_BUILD_TYPE`
at configure time does nothing and the binaries land in `build/Debug/`. Ask for
the configuration when you build instead:

```sh
cmake --build build --config Release
```

Triage a new title before committing to it:

```sh
pip install capstone pyelftools
python tools/apk_probe.py game.apk --out triage.md
```

## Documentation

**[Getting started](docs/GETTING-STARTED.md)** is the whole path from an APK to
a window with the game drawing in it, in the order you walk it. Everything else
is in [`docs/`](docs/README.md):

- **[ARCHITECTURE](docs/ARCHITECTURE.md)** — how the pieces fit, and the two
  execution paths.
- **[TRIAGE](docs/TRIAGE.md)** — deciding whether a title is portable, and the
  numbers that decide it.
- **[LOADER](docs/LOADER.md)** · **[SHIM](docs/SHIM.md)** ·
  **[RUNTIME](docs/RUNTIME.md)** · **[GRAPHICS](docs/GRAPHICS.md)** ·
  **[JNI](docs/JNI.md)** — one per subsystem.
- **[LIFTER](docs/LIFTER.md)** · **[VERIFICATION](docs/VERIFICATION.md)** —
  aarch64 to C, and how it is proved without arm64 hardware.
- **[BOOTING](docs/BOOTING.md)** — running a lifted program, and the six silent
  failures between a loaded engine and a frame on the screen.
- **[SIBLINGS](docs/SIBLINGS.md)** — what this kit and its 32-bit ARM
  counterpart owe each other.

## Milestones

- [x] **Loader.** Map, relocate, bind, protect; load APK-shipped dependencies.
- [x] **Shim.** libc, libc++, threads, locale, time, stdio, zlib, GL.
- [x] **Window.** SDL2 window, GL context, event loop.
- [x] **File I/O and memory.** POSIX file I/O, directories and `mmap`, written
      at Bionic's struct layouts rather than forwarded to the host's.
- [x] **Sockets and dynamic linking.** Including `dl_iterate_phdr` over the
      loaded images, which is how guest C++ exceptions find their `.eh_frame`.
- [x] **JNI bridge.** A `JNIEnv` the engine can call back through, and input
      translation. Per-title glue lives in the port; the reusable parts land here.
      Each mapped image gets its own `JNI_OnLoad` *before* the engine's
      constructors run, which is what Android does when Java loads a dependency
      by name — without it three of Tapped Out's constructors faulted on
      libNimble's uncached `JavaVM`.
- [x] **A frame on the screen.** `--loop` renders, presents, and forwards mouse
      events to `pointerPressed`/`Moved`/`Released` — the part the Java shell
      does on Android. See [BOOTING](docs/BOOTING.md).
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
- **fgrecomp** — *Family Guy: The Quest for Stuff*. The kit's second target, and the one that showed how much of it was general: 99.0% of
  functions lifted on the first run with no changes to the toolkit at all.

## Acknowledgements

No third-party code is vendored here. One design idea is borrowed and worth
naming:

- **[PvZ2Native](https://github.com/OptiJuegos/PvZ2Native)** (OptiJuegos,
  staFF6773, Eliandro4 — MIT) runs a native ARM32 Android title on the desktop
  by emulating the CPU and reimplementing Android around it, which is the same
  bet this kit makes. Its lifecycle driver queues each lifecycle message and
  drains the queue at the top of every `onDrawFrame` rather than acting the
  moment the call arrives. `--entry-at=frame:N` exists because of that: a call
  made between frames is not the same call made before the loop, and a title
  that defers its own setup can only be driven correctly if the host can say
  which one it meant. The idea is theirs; the code is not.
