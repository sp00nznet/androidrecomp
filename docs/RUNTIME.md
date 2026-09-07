# The runtime lifted code runs on

`runtime/arm64_context.h` is the guest CPU state and the operations lifted code
emits. `runtime/arm64_runtime.c` is the part that has to be code rather than a
macro: dispatch, traps, and the record of what the guest was doing.

## No address translation

The single most important thing about this design is what is *not* here. A
recompiled console needs a virtual memory manager, because guest pointers name
guest physical space. This does not, because **the guest's pointers are already
host pointers** — the loader maps the image at a real host address, and the shim
hands the engine the host's own `malloc`. A guest load is a host dereference.
That removes an entire layer that usually costs both code and per-access speed.

The one thing that is not position-independent is code addresses baked into the
instruction stream. `adrp` computes an address from the PC, and the PC in the
original image is an offset rather than where it was mapped — so those are
emitted relative to `image_base`, which the host fills in after loading.

## The context

`Arm64Ctx` holds `x[31]`, `sp`, the unpacked NZCV flags, `q[32]` vector
registers, `image_base`, and a shadow slot where a lifted `bl` parks its return
address.

Register access goes through macros rather than raw field access, because the
zero-extension rules are easy to forget and wrong exactly once: a 32-bit `W`
write zeroes the upper half of the `X` register, and a write to any FP register
narrower than 128 bits zeroes the rest of the vector. Those live in the setters
(`ARC_W_W`, `arc_s_w`, `arc_d_w`, `arc_q_w`) so no emitter has to remember.

`x[31]` is the zero register: reads give 0 and writes are discarded.

## Indirect branches

Every `blr`/`br` target is looked up in a sorted address → function table built
from the recovered function starts. Three things can happen:

1. **It is a lifted function.** Call it.
2. **It is a registered host function.** The guest reaches an import the same
   way it reaches a virtual method — load a GOT slot and branch — and the
   address in that slot is a *host* function the shim supplied, so it will never
   be in the dispatch table. `arc_register_native()` is what lets the dispatcher
   tell the two apart.
3. **Neither.** `arc_trap()`, loudly. An unlifted target reached at runtime is a
   bug to fix, not something to paper over.

### Calling out to the host

The thunk carries **twelve integer arguments and one integer result**: the eight
AArch64 passes in registers, and four more read from the guest stack where the
convention puts the rest. Handing a callee more arguments than it declares is
harmless — the caller sets them up and the callee ignores them — so one thunk
serves every arity up to twelve rather than needing one per signature.

Eight was not enough, and the way it failed is worth keeping: `glTexImage2D`
takes nine, the ninth being the pixel data, so the texture was uploaded from
whatever the driver found in that slot. Nothing reported a missing argument.

**It does not carry floating-point arguments.** Those live in `v0`-`v7`, and
placing them correctly needs per-signature knowledge the thunk does not have.
Anything that takes a float by value must be registered as a *context native*
instead. That is not a theoretical gap: bound through the thunk,
`glTexParameterf` set every texture parameter to `0` — not a valid enum, so
every set was silently rejected and every texture kept the default
`GL_NEAREST_MIPMAP_LINEAR`, which with no mip levels leaves it incomplete, which
samples as black.

### Context natives

```c
typedef void (*ArcCtxFn)(Arm64Ctx*);
void arc_register_ctx_native(uint64_t address, const char* name, ArcCtxFn fn);
```

A context native gets the whole guest state and reads its own arguments out of
it. The dispatcher checks these **first**, because they are a strict superset of
what the thunk can express. Three kinds of thing need them:

- **Variadic functions** — their arguments are spread across general registers,
  vector registers and the stack, and which one a given argument lives in
  depends on its type.
- **Functions taking floats by value** — `glClearColor`, `glTexParameterf`.
- **The JNI environment** — every one of its 256 slots, because a JNI call
  returning a `jfloat` must put its answer in `v0`, which an integer-returning
  thunk has no way to express.

### Calling *into* the guest

Some shim entry points take a callback: `pthread_once`'s initialiser,
`dl_iterate_phdr`'s visitor, a comparator. Those pointers are guest code, and
calling one as a host function pointer runs ARM instructions on an x86
processor — which surfaces as an access violation on *execute*, at an address
inside the game's own image, and so reads as a bad pointer in the guest rather
than as the host calling it wrongly.

`arc_call_guest()` is the only correct route. It gives the callback a stack of
its own rather than the host's, because lifted code addresses its frame through
the guest's stack pointer, and a fresh one per call keeps it safe to re-enter —
which matters, because an unwinder's callback can perfectly well take a lock or
throw.

## When it goes wrong

A fault in lifted code reports an address and nothing else. There is no host
call stack worth walking: the guest's frames are C frames belonging to 70,000
identically shaped functions. Four things fill that gap, and all of them are
platform-neutral.

| Mechanism | What it answers |
|---|---|
| `arc_set_recovery()` | Arms a `longjmp` target so a fault hands control back instead of killing the process. This is what lets one boot attempt enumerate *every* failure rather than the first. |
| `arc_frame_note()` | A ring of the guest functions entered, most recent first. A ring rather than a stack, so there is nothing to pop and no return path can be missed. `ARC_TRACE_GUEST=1` prints every entry instead. |
| `arc_trace_note()` | The last calls *out* to the host, and their arguments. This is what located an allocation of eighteen exabytes from a handle truncated to 32 bits, after five rounds of inference had not. `ARC_TRACE_CALLS=<substring>` prints them live. |
| `arc_set_explain()` / `arc_native_near()` | Turns a bare address into words. The runtime knows an indirect branch went somewhere unrecognised; only the host knows the somewhere is an unresolved import's slot, and which import. |

`arc_jmpbuf_for()` and `arc_longjmp()` exist because a guest `longjmp` has to
restore the *guest's* frame as well as the host's. Restoring only the host side
leaves the guest's callee-saved registers holding whatever the callee left in
them, and the first thing the returned-to function does is check its stack
canary against a frame that no longer matches — which reads as memory
corruption, the last place anyone would look for a missing register restore.

## The corner cases where C and the hardware disagree

Each of these produces a plausible wrong number rather than a crash, so each is
implemented explicitly rather than left to the C operator:

- An invalid operation (`0/0`, `inf - inf`, `0 * inf`) yields a NaN whose sign
  bit x86 sets and ARM clears. This affects all four basic operations, not just
  `sqrt`.
- ARM's `fmin`/`fmax` propagate NaN; C's deliberately do not. Only
  `fminnm`/`fmaxnm` match C.
- Float-to-integer conversion is saturating on ARM and *undefined behaviour* in
  C once the value does not fit, so it cannot be written as a cast at all.
