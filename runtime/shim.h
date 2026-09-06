// Resolves the engine's Android imports against the host.
//
// Three layers, in order:
//   1. Explicit implementations -- Android-only entry points that no host
//      runtime can provide, and library bindings we link ourselves.
//   2. Name aliases -- the same function under a different name on this host
//      (POSIX `strdup` is `_strdup` in the Microsoft CRT). Only where the
//      signature is genuinely identical; a same-name-different-ABI alias is a
//      crash that looks like a game bug.
//   3. The host C runtime, looked up by name at load time. Most of the 245
//      libc and 15 libm imports are ordinary standard C that the host already
//      has, so binding them by name costs no code per symbol.
//
// Whatever none of the three answers is the hand-written work list, and
// `arc_host` prints it.
#pragma once

#include <cstddef>
#include <cstdint>

namespace arc {

// Host address for an imported symbol, or 0 if nothing here provides it.
uint64_t ShimResolve(const char* name);

// How many symbols layer 1 covers, for the coverage report.
size_t ShimExplicitCount();

// A host function pointer handed to the guest at run time, from `dlsym` or
// `eglGetProcAddress`. Imports are announced to the dispatcher when they bind
// at load time; a pointer produced later has no such moment, and this is it.
// Without it the guest branches straight to host code the dispatcher has never
// heard of, and the branch is reported as going nowhere. Returns the address,
// so it can wrap a return value. Only ever pass a *host* address: registering
// a guest one would have it called as if it were host code.
uint64_t ShimHandOut(uint64_t address, const char* name);

// Threads, semaphores and thread-local keys. Kept in its own file because it
// carries real state rather than forwarding to something the host already has.
uint64_t ShimResolvePthread(const char* name);
size_t ShimPthreadCount();

// POSIX, BSD and locale entry points the host CRT does not export by name.
uint64_t ShimResolvePosix(const char* name);
size_t ShimPosixCount();

// Functions taking the guest's own va_list, which is a structure with
// separate register save areas rather than the host's flat pointer.
uint64_t ShimResolveVarargs(const char* name);

// Announces the variadic handlers to the dispatcher. Call once at startup.
void ShimRegisterVarargs();

// GL entry points, asked of the GL driver by name. Answers only once a context
// is current, which is why the window is opened before the engine is loaded.
uint64_t ShimResolveGL(const char* name);

// The Android asset manager, over an ordinary directory. Claimed only once a
// root is set, so that an unconfigured host leaves the names on the
// outstanding-import list rather than opening nothing.
uint64_t ShimResolveAsset(const char* name);
size_t ShimAssetCount();
void ShimSetAssetRoot(const char* path);
const char* ShimAssetRoot();

// File I/O, directories and memory mapping, at Bionic's struct layouts.
uint64_t ShimResolveFile(const char* name);
size_t ShimFileCount();

// Sockets, dynamic linking, process and system.
uint64_t ShimResolveSys(const char* name);
size_t ShimSysCount();

// Makes a loaded image visible to dlsym and dl_iterate_phdr. Call it for every
// image the host maps, or guest exception unwinding will not find .eh_frame.
class ElfImage;
void ShimRegisterImage(const ElfImage* image);

}  // namespace arc
