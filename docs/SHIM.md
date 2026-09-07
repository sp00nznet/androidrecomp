# The shim

An Android engine imports a few hundred symbols from Bionic, libc++, libm,
libGLES, libz and libandroid. The shim answers them.

## Three layers, in order

1. **Explicit implementations** — Android-only entry points no host runtime can
   provide, and library bindings we link ourselves (zlib, SDL's GL loader).
2. **Name aliases** — the same function under a different name on this host.
   POSIX `strdup` is `_strdup` in the Microsoft CRT. Only where the signature is
   *genuinely identical*: a same-name-different-ABI alias is a crash that looks
   like a game bug.
3. **The host C runtime, looked up by name.** Most of the 245 libc and 15 libm
   imports are ordinary standard C the host already has, so binding them by name
   costs no code per symbol. This is what keeps the shim small.

Whatever none of the three answers is the hand-written work list, and
`arc_host` prints it grouped by the library that owes it.

`ShimResolve()` in `runtime/shim.cpp` is the entry point and runs the
per-area resolvers first, because several of them must *win* over a by-name
binding that would otherwise succeed and be wrong.

## Where forwarding is the wrong answer

Most of the shim is a name lookup. These files exist because for their symbols
it is not — and in every case the failure is silent rather than loud.

### `shim_file` — Bionic's ABI, not the host's

The host has `open`, `stat` and `readdir` too, but they are not the same
functions. Bionic's `O_CREAT` is `0100`; the Microsoft CRT's is `0x100`.
Bionic's `struct stat` and `struct dirent` have layouts of their own, and the
engine allocated those structs and reads fields back at fixed offsets — so they
are filled in field by field at Bionic's offsets rather than letting the host
write its own shape into them. The layouts are the Linux arm64 kernel ABI, which
Bionic uses unchanged.

Descriptors are the host's own, because every call that consumes one routes
through here anyway.

`fopen` is shimmed for one reason: Bionic has no text mode, so a title writes
`"r"` and means `"rb"`. The UCRT takes `"r"` literally, drops every `0x0D` that
precedes a `0x0A`, and stops at the first `0x1A`. A pack file read that way
comes back shorter than it is with holes in the middle — which does not fail, it
decodes to an image zero pixels wide.

### `shim_pthread` — never look at the bytes

The engine allocates `pthread_mutex_t` and friends *inline* inside its own
structures, sized by Bionic's headers when it was compiled. Those sizes cannot
be changed, and guessing them wrong is silent memory corruption.

So the shim never depends on them. Every pthread call routes through this file,
so the guest never inspects the storage itself — which means it only has to *fit
inside*, not match the layout. Each object holds a single 32-bit id naming an
entry in a registry here. Bionic's smallest such type is `pthread_once_t` at
four bytes, so a `uint32_t` fits every one of them on every host, with no NDK
headers needed to prove it. Zero means "not created yet", which is Bionic's own
convention for a statically initialised mutex.

### `shim_sys` — sockets that swap their fields

`struct sockaddr_in` is the same on Linux and Windows, so addresses cross
unchanged. Two things do not, and both corrupt silently:

- **`struct addrinfo`.** Linux orders it `ai_addrlen, ai_addr, ai_canonname`;
  Winsock orders it `ai_addrlen, ai_canonname, ai_addr` — the two pointers are
  swapped, and `ai_addrlen` is `size_t` rather than `socklen_t`. Passed through,
  the engine gets a canonical name where it expects a sockaddr. Results are
  translated into guest-shaped nodes instead.
- **`SOL_SOCKET` option numbers.** `SO_REUSEADDR` is 2 on Linux and 4 on
  Windows; `SO_RCVTIMEO` is 20 against `0x1006`. Unmapped, a timeout request
  silently sets something else.

This file also holds `dlopen`/`dlsym`/`dl_iterate_phdr` over the loaded images —
which is how guest C++ exceptions find their `.eh_frame`.

### `shim_varargs` — a va_list is not a pointer

On aarch64 a `va_list` is a 32-byte structure holding two register save areas,
one for integers and one for floating point, plus a cursor into the stack:

```c
void* stack;  void* gr_top;  void* vr_top;  int gr_offs;  int vr_offs;
```

The host's `va_list` is a flat pointer walking one contiguous area. Handing one
to the other compiles, links, runs, and formats nonsense — and the *return
value* is wrong too, which is worse than the visible garbage: a caller that asks
`vsnprintf` how long the result would be, allocates that much and copies it,
copies the wrong number of bytes.

So these are reimplemented over the guest's own structure. They are registered
as **context natives** (see [RUNTIME.md](RUNTIME.md)) because they need the
guest's registers, not eight integers.

### `shim_posix` — three kinds of gap

Functions the host *has but hides*: MSVC defines `printf`, `sprintf`, `wmemcpy`
inline in headers rather than exporting them from `ucrtbase.dll`, so a by-name
lookup misses code that is right there. Taking their address binds them.

Functions the host has *under different terms*: `gmtime_r` and `gmtime_s` swap
their arguments; `fseeko` is `_fseeki64`. Wrapped, never aliased.

Functions only glibc and Bionic have: `asprintf`, `memrchr`, `strtok_r`.
Written out.

### `shim_zlib` — the same struct, two sizes

`uLong` is `unsigned long`: 8 bytes on Android arm64, 4 on Windows. So
`z_stream` is 112 bytes in the guest and 88 here, with `next_out` and everything
after it at different offsets.

Bound straight through, `inflateInit2_` compares the caller's `stream_size`
against its own and answers `Z_VERSION_ERROR`. The engine does not check, calls
`inflate` on an uninitialised stream, gets `Z_STREAM_ERROR`, and carries an
empty buffer away — every asset in a pack decompressing to nothing.

The shim reads and writes the guest's struct by offset and keeps a host
`z_stream` beside it, in the guest's own `state` field, which is opaque to the
caller by contract. The guest's allocator hooks are deliberately not carried
over: they are arm64 code, and calling one from the host would need a guest
context this side of the boundary does not have.

### `shim_asset` — a directory, not an emulation

An APK carries a title's own files under `assets/`, and many engines read every
one of them through `AAssetManager` rather than through `open`. There is nothing
to emulate: the APK is a zip and the host has a filesystem, so this is an
extracted directory. Nothing is decompressed, cached or rewritten.

One piece of state surprises: `AAssetDir_getNextFileName` returns a pointer the
caller may hold until it asks again, so the directory keeps the name it last
handed out.

### `shim_gl` — see [GRAPHICS.md](GRAPHICS.md)

GL is mostly a by-name lookup through the live driver. The exceptions are where
the *language* or the *calling convention* differs, and they are large enough to
have their own document.

## Adding to it

Run `arc_host` against the library. Everything it lists is a symbol nothing
answers yet, grouped by the library that owes it. Work down the list; the
grouping tells you which file it belongs in.
