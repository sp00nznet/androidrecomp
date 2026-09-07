# Documentation

**Have an APK and want to reproduce this?** Start with
[GETTING-STARTED.md](GETTING-STARTED.md) — the whole path, in the order you walk
it.

For how it works rather than how to run it, start with
[ARCHITECTURE.md](ARCHITECTURE.md).

## By piece

| Document | Covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it all fits, and the two execution paths. |
| [LOADER.md](LOADER.md) | `runtime/elf_image` — mapping, relocation, imports, dependencies. |
| [SHIM.md](SHIM.md) | `runtime/shim*` — the three layers, and every place forwarding is the wrong answer. |
| [RUNTIME.md](RUNTIME.md) | `runtime/arm64_context.h`, `runtime/arm64_runtime.c` — guest state, dispatch, calling in and out, what a fault reports. |
| [GRAPHICS.md](GRAPHICS.md) | `runtime/window`, `runtime/shim_gl` — the context, GLSL ES translation, and the three silent differences. |
| [JNI.md](JNI.md) | `runtime/jni_env` — discovering a title's host contract, and a `JNIEnv` with nothing behind it. |
| [LIFTER.md](LIFTER.md) | `tools/lifter.py` — aarch64 to C, and what "coverage" does and does not mean. |
| [VERIFICATION.md](VERIFICATION.md) | Proving all of it without arm64 hardware. |

## By task

| I want to… | Read |
|---|---|
| Port a title from scratch | [GETTING-STARTED.md](GETTING-STARTED.md) |
| Decide whether a title is portable at all | [TRIAGE.md](TRIAGE.md) |
| Add a missing import | [SHIM.md](SHIM.md) |
| Get a lifted program to boot | [BOOTING.md](BOOTING.md) |
| Work out why the window is black | [GRAPHICS.md](GRAPHICS.md) |
| Drive the engine from the host | [JNI.md](JNI.md) |
| Understand a trap or a fault report | [RUNTIME.md](RUNTIME.md) |

## Also here

- [SIBLINGS.md](SIBLINGS.md) — what this kit and its 32-bit ARM counterpart owe
  each other. Written down because otherwise each pays the same costs twice.
