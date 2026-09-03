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

// Threads, semaphores and thread-local keys. Kept in its own file because it
// carries real state rather than forwarding to something the host already has.
uint64_t ShimResolvePthread(const char* name);
size_t ShimPthreadCount();

// POSIX, BSD and locale entry points the host CRT does not export by name.
uint64_t ShimResolvePosix(const char* name);
size_t ShimPosixCount();

// GL entry points, asked of the GL driver by name. Answers only once a context
// is current, which is why the window is opened before the engine is loaded.
uint64_t ShimResolveGL(const char* name);

}  // namespace arc
