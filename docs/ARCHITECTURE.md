# Architecture

A great many Android games are a thin Java shell wrapped around a large native
`.so`. The Java side owns a window, a GL context and a touch handler and calls
into the engine through a handful of JNI methods; everything that matters —
renderer, simulation, game logic — is ARM64 machine code in the library.

So a port is four jobs: **load** the library, **answer** what it imports,
**drive** it the way Java did, and, on a machine that is not ARM, **translate**
its instructions.

## The pieces, in the order a run touches them

```
        libengine.so + the libraries the APK ships beside it
                            |
   [ elf_image ]  map, relocate, bind imports, collect constructors
                            |
        +-------------------+--------------------+
        |                                        |
   arm64 host                             any other host
   image is callable                      [ lifter.py ] -> generated C
        |                                        |
        +-------------------+--------------------+
                            |
   [ arm64_runtime ]  dispatch, traps, calls out to the host
                            |
        +---------+---------+---------+----------+
        |         |         |         |          |
     [ shim ] [ shim_gl ] [ jni_env ] [ window ] [ shim_asset ]
     libc      the driver   JNIEnv     SDL2       assets/ on disk
                            |
   [ arc_boot ]  constructors, entry points, the frame loop
```

| Piece | Document |
|---|---|
| `runtime/elf_image` | [LOADER.md](LOADER.md) |
| `runtime/shim*` | [SHIM.md](SHIM.md) |
| `runtime/shim_gl`, `runtime/window` | [GRAPHICS.md](GRAPHICS.md) |
| `runtime/jni_env` | [JNI.md](JNI.md) |
| `runtime/arm64_context.h`, `runtime/arm64_runtime.c` | [RUNTIME.md](RUNTIME.md) |
| `tools/lifter.py` | [LIFTER.md](LIFTER.md) |
| `tools/lift_verify*.py`, `tools/selftest.py` | [VERIFICATION.md](VERIFICATION.md) |
| `tools/apk_probe.py`, `tools/arc_host.cpp`, `tools/dex_contract.py` | [TRIAGE.md](TRIAGE.md) |
| `tools/arc_boot.cpp` | [BOOTING.md](BOOTING.md) |

## Two execution paths, one host

The host program is needed either way, so it comes first.

**Native arm64.** On Apple Silicon, Windows-on-ARM and arm64 Linux the engine's
instructions already run; what is missing is Bionic and Android. Once the shim
is complete the mapped image is callable directly — a playable port with no
lifting at all, and the reference a lifted build gets diffed against.

**Lifted x86-64.** The same host, linked against generated C instead of a mapped
ELF. Everything above the dispatcher is identical; only where the instructions
come from changes.

This is why the loader and the shim are developed and verified on whatever
machine you have. They are not the arm64 half of the problem.

## Why guest pointers are host pointers

A recompiled console needs a virtual memory manager, because guest pointers name
guest physical space. This does not. The loader maps the image at a real host
address and the shim hands the engine the host's own `malloc`, so a guest load is
a host dereference and an entire layer disappears — along with its per-access
cost.

The consequence runs through everything: a `jobject` can be a real pointer, a
`FILE*` can be the host's, a socket can be the host's descriptor. The shim only
has to reproduce an ABI where the guest *inspects the bytes itself*, which is a
much smaller set than "everything Android does". [SHIM.md](SHIM.md) is
organised around exactly that distinction.

## Why the kit is a separate repository

A port supplies its own JNI bridge and host contract and links this. Nothing
title-specific belongs here.

That separation was made early on purpose, and it has already paid: a second,
unrelated engine surfaced a shim bug and a whole class of missing function
boundaries that the first engine had been quietly suffering from too, and
twenty-seven of its static constructors were won without touching that port at
all. Extracting a reusable kit *after* a port has grown into it is painful and
rarely happens.

[SIBLINGS.md](SIBLINGS.md) is what this kit and its 32-bit ARM counterpart owe
each other — the list of things each learned at a cost that the other is cheaper
to build in from the start.
