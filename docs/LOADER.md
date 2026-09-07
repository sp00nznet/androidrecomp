# The loader

`runtime/elf_image` maps an aarch64 ELF shared object into host memory,
relocates it, and binds its imports through a resolver. It has no dependencies
beyond the standard library.

This is the piece both execution paths need. On an arm64 host the mapped image
is directly callable, which is how an engine runs before a lifter exists. On any
other host it cannot execute — but the same load (segment layout, relocation,
symbol resolution) is exactly what the lifter consumes, so it is developed and
verified everywhere.

## What Load() does

```cpp
arc::ElfImage image;
image.Load(path, resolve, &err);   // resolve: name -> host address, or 0
```

1. **Reads the program headers** and lays the `PT_LOAD` segments out at their
   recorded virtual addresses, in one reservation, so the image's internal
   offsets stay correct.
2. **Applies relocations.** Four types cover an NDK library:
   `R_AARCH64_RELATIVE` (base + addend), `R_AARCH64_GLOB_DAT` and
   `R_AARCH64_JUMP_SLOT` (a symbol's address into the GOT/PLT), and
   `R_AARCH64_ABS64` (a symbol's address into arbitrary data). Anything else is
   reported rather than skipped.
3. **Binds every undefined symbol** through the caller's resolver. What comes
   back is a host address; what does not come back is recorded on `imports()`
   as unresolved.
4. **Collects `DT_INIT_ARRAY`**, the static constructors, for the host to run.

`Protect()` applies the page protections from the program headers, and is
separate from `Load()` because relocation has to run against writable memory. It
only means anything where the image will actually execute.

## Unresolved imports point somewhere deliberate

An import nothing satisfies is not left as zero. It is pointed into a guard
page, so a call through it faults at a distinctive address the host can
recognise and name, rather than at address 0 alongside every other null
dereference in the process.

## Dependencies

`ReadNeeded()` reads `DT_NEEDED` from a file without mapping it, so a host can
load an image's APK-shipped dependencies *first* and let them satisfy the
engine's imports. That is what answers `libc++_shared.so`'s NDK-mangled
(`_ZNSt6__ndk1...`) symbols, which no host STL can provide.

The rule: **if the APK ships it, load it.** Everything else is an Android system
library and falls to the shim. One exception worth knowing — a shipped
`libopenal.so` resolves plenty but drags in `libOpenSLES` imports, because its
audio backend is Android's. Link native openal-soft instead.

## What it exposes afterwards

| Accessor | Why a host wants it |
|---|---|
| `Lookup(name)` | Host address of an export — how an entry point is called. |
| `ExportsWithPrefix("Java_")` | Enumerates a library's JNI entry points. This is how a title's host contract is discovered. |
| `SymbolAt(addr, &off)` | The defined function containing an address. Shipped Android libraries keep their `.dynsym`, so a frame trail of bare offsets becomes a trail of names. |
| `imports()` | Name, version, bound address, and whether it resolved. The port's work queue. |
| `init_array()` | The static constructors, in order. |
| `phdrs()` / `phnum()` | Handed to `dl_iterate_phdr`, which is how the C++ unwinder finds each image's `.eh_frame` — so guest exceptions depend on them. |
| `segments()`, `span()`, `base()` | Where it landed, for attributing an address to an image. |

## Verifying it without a game

`tools/selftest.py` hand-assembles a synthetic arm64 shared object that exports
a JNI-shaped contract and exercises all four relocation types, loads it with
`arc_host`, and checks the result. No APK, no NDK, no arm64 hardware. See
[VERIFICATION.md](VERIFICATION.md).
