# Graphics

Two files: `runtime/window` opens a window and a GL context, and
`runtime/shim_gl` binds the engine's GL imports to the driver.

## The window

`runtime/window` is the desktop stand-in for Android's `GLSurfaceView`: an SDL2
window, a GL context, an event loop, and a queue of pointer events in the terms
the engine's JNI bridge already speaks.

Two ordering rules are not incidental.

**Create the context before loading the engine.** The engine's GL imports bind
through `SDL_GL_GetProcAddress`, which needs a current context to answer — so
the window has to exist first, exactly as it does on Android where Java holds a
surface before it calls in. Load the engine first and its GL slots are left
unbound, and an unbound slot is not a missing function, it is a branch into
nothing.

**Make the context current on whichever thread runs the guest.** A GL context
belongs to one thread at a time, and the guest gets a thread of its own because
it needs a far larger stack than a default one. Without this the engine's GL
calls have no context to act on — and that does not fail loudly: `glGetString`
answers null and the engine calls `strlen` on the result.

`--gl=MAJOR.MINOR` asks for a particular version; 0 takes whatever the driver
offers, which has been GL 2.1 compatibility in practice. That default suits an
engine with a fixed-function GLESv1_CM tail and is old for one written against
GLES2/GL3, so which to ask for is a property of the title rather than of the kit.

## GL by name

Desktop GL exports most GLES2 entry points under identical names and signatures,
so once a context is current the loader asks the driver for each symbol
directly. That makes most of this layer cost no code per symbol — the same trick
as looking libc up in the host CRT, one level down.

`eglGetProcAddress` is bound unconditionally, because some engines resolve entry
points that way rather than through the import table, and the guest branches
*through* an empty slot rather than checking it.

Whatever does not come back is the genuinely ES-only tail: the fixed-function
GLESv1_CM calls, and the float-suffixed ES variants like `glOrthof` that desktop
GL spells without the `f`. Those are the ones worth hand-writing, and `arc_host`
lists them by name rather than making you guess in advance.

## Where it is not a pass-through

Three things differ where the API does not, and all three fail in the same way:
a full frame of correct-looking draw calls, no GL error anywhere, and a black
window.

### GLSL ES is not desktop GLSL

An engine written for GLES2 hands the driver GLSL ES. `precision mediump
float;` is a statement desktop GLSL has no grammar for, and
`lowp`/`mediump`/`highp` appear inline on declarations.

So shader source is translated on the way through: the version line is replaced,
`precision` statements are dropped, the qualifiers are defined away. Everything
else of this vintage — `attribute`, `varying`, `texture2D`, `gl_FragColor` —
means the same in both. Both are replaced by a *blank line* rather than deleted,
so a compiler error still names the line the author would find in the file.

A rejected shader does not raise anything. The program links to nothing, every
uniform location comes back as -1, and the frame draws. So a compile or link that
still fails is **reported**, because nothing else will.

### Floats do not survive the thunk

`glClearColor`, `glTexParameterf`, `glLineWidth` and `glUniform1f` take a float
by value, which lives in `v0` and which the dispatcher's twelve-integer thunk
cannot place. They are registered as context natives and read `v0` themselves.
See [RUNTIME.md](RUNTIME.md).

Bound through the thunk, `glTexParameterf` set every parameter to `0`. That is
not a valid enum, so every set was rejected and every texture kept the default
`GL_NEAREST_MIPMAP_LINEAR` — which with no mip levels leaves the texture
*incomplete*, and an incomplete texture samples as `(0,0,0,1)` everywhere.

### Desktop GL reserves attribute 0

A compatibility context keeps generic attribute 0 aliased to the fixed-function
vertex array and generates no primitives at all unless array 0 is enabled. GLES
has no such rule, so an engine is free to start its attributes at 1. The shim
shifts the indices down by one, consistently for the binding and for the arrays.

> This one is a shift, not a mapping table. A title that uses 0 and 1 together
> needs the table.

## Finding out which of them it is

The diagnostics that split the problem, all off unless asked for:

| Variable | What it shows |
|---|---|
| `ARC_TRACE_GL=1` | Every `glTexImage2D`: bound texture, level, dimensions, internal format, type, and the first bytes of the pixel data. All-zero bytes means the decode; anything else means the sampler state. |
| `ARC_TRACE_SHADERS=1` | The translated source of every shader, as the driver sees it. |
| `ARC_GL_FLAT=1` | Replace every fragment shader with solid red. An empty frame with this on means the geometry never arrives, and neither the texture nor the blend state is worth looking at. |
| `ARC_GL_FLAT=tex` | Paint the diffuse texture opaque. An empty frame with *that* on means the sampler, not the colour it is multiplied by. |
| `ARC_GL_TINT=1` | Clear to a colour nothing in the game would produce. A capture that comes back that colour says the context, the buffer and the readback are all sound. |

Compile and link failures, GL errors on draws and on texture uploads are
reported without asking, because each of them is otherwise invisible.

`arc_boot --shot=FILE.ppm` writes the frame the driver actually rasterised,
which is the only evidence that a port renders. Binary PPM: no encoder, no
dependency, and every image tool reads it.
