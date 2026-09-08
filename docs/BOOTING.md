# Building and running a lifted program

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
cmake --build build-lifted --target arc_boot     # --config Release on Windows
./build-lifted/arc_boot libengine.so
```

`arc_boot` runs the lifted program's static constructors and then, optionally,
a named entry point. Constructors are the right first thing to run: they
allocate, take locks and build tables, touching a large part of the shim
without needing a window, a JNI environment or a server. Failures are recovered
rather than fatal — a boot that dies on the first bad constructor tells you one
thing per run, one that keeps going tells you the shape of what is left.

On this engine **all 1,527 constructors run** with no faults, and `init` prints
the engine's own startup banner through the logging shim. On the second engine —
a different vendor, a different renderer, no title-specific work — **all 1,202
run**.

Then drive it the way the Java shell does. `--loop` renders, presents, and
forwards mouse events to the engine's pointer entry points; `--frames` and
`--shot` make a run reproducible and leave a picture behind:

```sh
B=Java_com_bight_android_jni_BGCoreJNIBridge
./build-lifted/arc_boot --window --loop --assets=work/assets \
  --entry=${B}_init      --args=obj \
  --entry=${B}_OGLESInit --args=1280,720 \
  --entry=${B}_OGLESResize --args=1280,720 \
  --entry=Java_com_ea_simpsons_ScorpioJNI_init --args=str:/path/to/data \
  --entry=${B}_resume \
  libengine.so
```

The order is Android's, and it is not optional: the GL surface exists before the
game boots, because the game's boot allocates out of the renderer's heap.

### The setup call that has to be made by hand

The order being Android's is necessary and it is not always sufficient. An
engine can hold a piece of setup behind a one-shot -- a flag it tests once,
acts on, and clears -- and that one-shot can fire before the thing it depends
on exists. Android gets away with it because Java calls back in again later;
a host that issues its entry points once and then renders does not.

Tapped Out is the worked example. Its font and menu registry is initialised
from a function gated on a byte that only `LifecycleStart` sets, and that
function is reached from a one-shot which fires during the game's own `init`
-- before `LifecycleStart`, because `LifecycleStart` faults if the game has
not been built yet. So it bails, clears its flag, and the chance does not come
back. The registry stays empty, every font lookup answers null, and the first
menu to add a null child faults on frame one.

Nothing in the entry order fixes this, because no order satisfies both
constraints. The initialiser takes no arguments -- it fetches the singleton
itself -- so it can simply be called:

```sh
  --entry=0x12c89dc ```

`--entry` takes a raw image offset as well as a name, which is what makes an
unexported function callable at all. Two things make one findable: the fault's
guest call stack names the function that faulted and everyone above it, and
`--peek` reads the byte a branch turned on. Between them the question "why was
this skipped" is answerable without a debugger.

A one-shot spent too early looks like nothing at boot and like a null
dereference much later, so it is worth suspecting whenever a fault is a null
that something should have filled in.

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

## Getting a frame on screen

Every step between "the engine's constructors run" and a title drawing its own
splash screen failed *silently*. None raised an error, none crashed, and each
produced exactly the frame a game that had not been written yet would produce: a
black window with a full set of correct-looking draw calls behind it. They are
worth writing down because the next title will hit the same ones.

**A dependency's `JNI_OnLoad` was never called.** Java calls it once per library
it loads by name, and libNimble caches the `JavaVM` there. Three of the engine's
own constructors reach into libNimble, found a null, and faulted. Calling it for
every mapped image, before the main image's constructors, took the fault count
from three to zero.

**The game's boot entry point was not in the contract.** The fourteen
`BGCoreJNIBridge` methods look like the whole host contract, and they are not:
`ScorpioJNI_init` is what builds the game and installs its first state. Without
it `OGLESRender` returned after six guest calls, having found no state to
update. With it, a frame runs eight hundred.

**`writablePath` was answered with the wrong directory.** Android hands a title
one data directory; it reads its shipped content out of that *and* writes beside
it. Answering with the parent of the asset root put every pack one directory out
of reach — which showed up not as a missing file but as a shader whose body was
empty, a program that linked to nothing, and every uniform location at -1.

**GLSL ES is not desktop GLSL.** `precision mediump float;` is a statement
desktop GLSL has no grammar for. `runtime/shim_gl` rewrites the version line,
drops the precision statements, defines the qualifiers away, and — the part that
matters — *reports* a compile or link that still fails, because nothing else
will.

**zlib's `z_stream` is a different size on each side.** `uLong` is
`unsigned long`: 8 bytes on Android arm64, 4 on Windows, so the struct is 112
bytes in the guest and 88 here with every field after `next_out` at a different
offset. `inflateInit2_` compares the caller's `stream_size` against its own,
answers `Z_VERSION_ERROR`, and the engine does not check — so every packed asset
decompressed to nothing, every image was zero pixels wide, and the window stayed
black. `runtime/shim_zlib` reads and writes the guest's struct by offset and
keeps a host `z_stream` in the guest's own opaque `state` field.

**The dispatcher's thunk carries no floating-point arguments.** They live in
v0-v7 and the twelve-integer thunk cannot place them, so `glTexParameterf` set
every texture parameter to 0 — not a valid enum, so every set was rejected and
every texture kept the default `GL_NEAREST_MIPMAP_LINEAR`. With no mip levels
that leaves a texture *incomplete*, and an incomplete texture samples as black.
A whole frame of correct draws, in black, with no GL error anywhere. The four GL
entry points that take a float by value are registered as context natives and
read v0 themselves.

The tools that found these are in the box and stay there: `--peek` walks a
pointer chain and hex-dumps what it lands on, `--shot` writes the frame the
driver actually rasterised, `ARC_TRACE_GUEST` prints every guest function
entered, and `ARC_GL_FLAT` replaces the fragment shader with a solid colour so
that "the geometry never arrives" and "the texture is black" stop looking alike.
