# Getting started

You have an APK. This is the whole path from there to a window with the game
drawing in it, in the order you actually walk it.

Nothing here is title-specific. Where a step needs a decision from you, it says
so and says what the decision is.

## 0. What you need

| | Why |
|---|---|
| CMake 3.20+ and a C++17 compiler | Builds the kit. |
| Python 3.9+ | The lifter and every tool. |
| `pip install capstone pyelftools` | Disassembly and ELF parsing, for triage and lifting. |
| `pip install unicorn` | Only for verification. Skip it until you change the lifter. |
| zlib, SDL2 | Optional. Without them those imports simply stay on the work list. |

On Windows, get zlib and SDL2 from vcpkg and pass the toolchain file. It only
takes effect on a fresh cache, so delete `build/` if you add it later:

```sh
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

The Visual Studio generator is multi-config, so `-DCMAKE_BUILD_TYPE` at
configure time does nothing there and the binaries land in `build/Debug/` unless
you pass `--config` when you build. Every `./build/arc_host` below is
`build\Release\arc_host.exe` on Windows.

## 1. Build the kit and check it works

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

python tools/selftest.py
```

`selftest.py` hand-assembles a synthetic arm64 library and loads it. It needs no
APK, no NDK and no arm64 hardware, and it is the fastest way to know your build
is sound before you blame the game.

## 2. Unpack the APK

An APK is a zip.

```sh
mkdir game && cd game && unzip ../game.apk
```

You want two things out of it:

- `lib/arm64-v8a/` — the engine and every library shipped beside it. **Keep them
  together in one directory.** The loader reads `DT_NEEDED` and loads an image's
  APK-shipped dependencies itself, and it looks for them next to the engine.
- `assets/` — the title's own files. Copy this somewhere writable; see step 8.

If there is no `arm64-v8a` directory, stop: this kit is arm64 only.

## 3. Decide whether it is worth doing

```sh
python tools/apk_probe.py game.apk --out triage.md
```

Four numbers decide whether a port is weeks or years. [TRIAGE.md](TRIAGE.md)
explains each in full; the short version:

- **Functions recovered from `.eh_frame`** — should be near 100%. This is the
  hardest problem in static recompilation and NDK builds hand it to you. Low
  coverage here is the main red flag.
- **Undefined symbols** — the shim surface. A few hundred standard POSIX/GL
  names is routine. Thousands of exotic ones is not.
- **Indirect branches** — C++ vtable dispatch. Expected; just sizing.
- **`svc` sites, exotic relocations, TLS** — small counts mean a small loader.

## 4. Find out what it still needs

```sh
./build/arc_host game/lib/arm64-v8a/libengine.so
```

This maps the image, relocates it, binds its imports through the shim, and
prints everything nothing yet provides, **grouped by the library that owes it**.
That list is your work queue and it shrinks as you go.

Add a `--window` and it opens a GL context first, which resolves the GL imports
too — they bind by asking the driver for each name, and that needs a context.

When something is missing, [SHIM.md](SHIM.md) says which file it belongs in, and
— more usefully — which kinds of symbol must *not* simply be forwarded to the
host.

## 5. Find the entry points the Java shell used

The Java side is gone, so you have to call what it called.

```sh
./build/arc_host game/lib/arm64-v8a/libengine.so        # every Java_* export
python tools/dex_contract.py game.apk --grep Bridge     # and their signatures
```

The exports give you names; the dex gives you argument types, and you need both
— an entry point handed a zero width and height sets up a zero-sized surface and
fails much later, which reads as a porting bug rather than a missing argument.

Write the ones you will drive into a text file, one per line, and have
`arc_host` verify they all resolve:

```sh
./build/arc_host --contract=contract.txt game/lib/arm64-v8a/libengine.so
```

**Two warnings, both learned the hard way.** The obvious bridge class may not be
the whole contract — a title's *boot* can live on a different class entirely, and
without it the render tick runs and draws nothing. And the *order* matters:
follow Android's, because the GL surface usually has to exist before the game
boots. [JNI.md](JNI.md) has the detail.

## 6. On an arm64 machine, you are nearly done

On Apple Silicon, Windows-on-ARM or arm64 Linux the engine's instructions
already run. Finish the shim and the bridge and `arc_host --window` drives the
mapped image directly — no lifting involved. Skip to step 8.

Everywhere else, continue.

## 7. Lift it

Start with the number, not the output:

```sh
python tools/lifter.py game/lib/arm64-v8a/libengine.so --report
```

`--report` says what fraction of real instructions the emitters cover and lists
what is missing. Watch **function** completeness rather than instruction
completeness — they move very differently, and only one decides whether a build
is possible, because a single unsupported instruction fails the whole function
it sits in. [LIFTER.md](LIFTER.md) explains why.

Then generate. Pass every library the APK ships beside the engine: a call into
`libc++_shared.so` lands in ARM code like any other.

```sh
python tools/lifter.py game/lib/arm64-v8a/*.so --out generated/ --shards 64
```

If you changed the lifter, prove it before trusting it:

```sh
python tools/lift_verify.py game/lib/arm64-v8a/libengine.so
python tools/lift_verify_fn.py game/lib/arm64-v8a/libengine.so --generated generated/
```

Both run against Unicorn on whatever machine you have. [VERIFICATION.md](VERIFICATION.md).

## 8. Build the lifted program

```sh
cmake -S . -B build-lifted -DARC_LIFTED_DIR=generated
cmake --build build-lifted --target arc_boot     # --config Release on Windows
```

This is a large amount of C — expect it to take a while and want memory.

## 9. Boot it

Constructors first. They allocate, take locks and build tables, so they exercise
a large part of the shim without needing a window, a JNI environment or a server:

```sh
./build-lifted/arc_boot game/lib/arm64-v8a/libengine.so
```

Failures are recovered rather than fatal, so one run enumerates *every* bad
constructor rather than the first. Expect some; work through them.

Then call the contract, in Android's order, with the assets directory you copied
out in step 2:

```sh
./build-lifted/arc_boot --window --assets=/path/to/assets \
  --entry=Java_com_example_Bridge_init      --args=obj \
  --entry=Java_com_example_Bridge_OGLESInit --args=1280,720 \
  game/lib/arm64-v8a/libengine.so
```

`--args` takes integers, `obj` for a Java object the engine only passes back
through JNI, and `str:TEXT` for a String.

**Point `--assets` at a directory you can write to.** Android hands a title one
data directory and it both reads its shipped content out of that *and* writes
beside it, so this one path is usually both.

Finally, drive it like the Java shell did — render, present, forward input:

```sh
./build-lifted/arc_boot --window --loop --assets=... --entry=... libengine.so
```

## 10. When it does not work

It will not fail loudly. Almost everything between a loaded engine and a frame
fails *silently*, producing a black window behind a full set of correct-looking
draw calls. [BOOTING.md](BOOTING.md) lists the six that cost the most time, and
these are the tools that found them:

| | |
|---|---|
| `--constructors=N` | Stop after N. Bisects a bad one fast. |
| `--peek=OFF[/OFF…][:LEN]` | Walk a pointer chain from the image base and hex-dump what it lands on. How you read one field of an engine singleton with no debugger. |
| `--entry-at=frame:N` | Follows an `--entry` and issues it at the top of frame N instead of before the loop. Android hands an engine its lifecycle messages and the engine acts on them at the top of a frame, so a call made between frames is not the same call made before the loop -- and a one-shot that runs too early is spent. (Idea from [PvZ2Native](https://github.com/OptiJuegos/PvZ2Native); no code taken.) |
| `--frames=N`, `--shot=FILE.ppm` | Run a fixed number of frames and write the one the driver actually rasterised. Reproducible, and it is the only real evidence a port renders. |
| `ARC_TRACE_CALLS=<list>` | Every call out to the host whose name matches any comma-separated substring; `*` matches all. Paths are printed as paths. A sequence is what answers most questions -- which calls a socket got between `connect` and `close` is not visible one name at a time. |
| `ARC_TRACE_GUEST=1` | Every guest function entered. Enormous, and the way to see which branch a state machine took. |
| `ARC_TRACE_JNI=1` | Every class, method and field the engine asks for by name. |
| `ARC_TRACE_FRAMES=1` | The ring of guest functions entered, after each entry point. |
| `ARC_TRACE_ASSETS=1` | Every asset the engine asks the asset manager for, and whether it was found. |
| `ARC_TRACE_ZLIB=1` | Every `inflate`/`deflate`, with its return code. Failures print without asking. |
| `ARC_TRACE_NET=1` | Every connect, send, recv and `getsockopt`, with the address and the error. Separates "never dialled" from "dialled and never spoke". |
| `ARC_TRACE_FILES=1` | Every path opened, stat'd or created, and whether it was there. |
| `ARC_TRACE_PREFS=1` | Every preference key the title reads, and what it was answered with. |
| `ARC_TRACE_GL=1`, `ARC_GL_FLAT=1\|tex` | See [GRAPHICS.md](GRAPHICS.md). These separate "the geometry never arrives" from "the texture is black". |

Read the report at the end of a run, not just the crash. It names every JNI
field and method the engine asked for and could not be answered — each of which
otherwise reads as a plausible zero somewhere much later.

## Telling the host what the device is

Some of what a title asks Java for is a real property of a real device, and a
host cannot infer it. Those are environment knobs rather than invented
constants, because getting one wrong is not visible and the right value is
yours to know:

| | |
|---|---|
| `ARC_SERVER` | Base URL the title should use for its own server. On Android this is patched into the library by hash and offset before installation; here it is a setting. |
| `ARC_SERVER_REDIRECT=host:port` | Send every outbound connection there instead. For the hosts you could not name in advance — a content CDN the client has compiled in. TLS is left alone: a plain-HTTP sidecar cannot answer a handshake, and capturing a title's internet check guarantees it fails. |
| `ARC_APP_VERSION` | The version the title believes it is, in three components. Not cosmetic: a title asks its content server for an index of entries tagged by version and picks the one its own version selects. Claiming `1.0.0` against a catalogue starting at 4.x selects nothing, and the loading screen waits forever for a download it never asked for — with the server showing a clean 200 for the index and nothing after it. |
| `ARC_LANG`, `ARC_LOCALE` | The device locale. A string the title does not know is index zero, which is also what English is, so the two are not distinguishable downstream. |
| `ARC_THREAD_POLLS` | How many times to answer "still working" before a Java worker thread reports done. Zero compresses to nothing a wait the engine advances its own state machine during. |

## Where to put your own code

Nowhere in this repository. A port is its own repo that vendors this one as a
submodule and adds what is genuinely about the title: its host contract, its
boot order, its glue. That separation is the whole point —
see [ARCHITECTURE.md](ARCHITECTURE.md).
