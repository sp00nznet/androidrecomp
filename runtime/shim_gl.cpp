// The 50 GL imports, bound by name.
//
// Desktop GL exports most GLES2 entry points under identical names and
// signatures, so once a context is current the loader can ask the GL driver for
// each symbol directly. That makes this whole layer cost no code per symbol --
// the same trick as looking libc up in the host CRT, one level down.
//
// Whatever does not come back is the genuinely ES-only tail (the fixed-function
// GLESv1_CM calls, and the float-suffixed ES variants like glOrthof that
// desktop GL spells without the f). Those are the ones worth hand-writing, and
// arc_host lists them by name rather than making us guess in advance.

#include <cstring>

#include "shim.h"

#if defined(ARC_HAVE_SDL2)
#include <SDL.h>
#endif

namespace arc {

// EGL's own loader, which the engine uses for the entry points it resolves
// lazily rather than through its import table. Leaving it unbound costs more
// than one symbol: the guest branches *through* the empty slot and stops
// there, which is what a cocos2d-x GL view does before it ever opens. Bound
// unconditionally, so the slot always holds something callable -- with no
// context it answers null, which the engine can see and act on, rather than
// jumping into nothing.
uint64_t EglGetProcAddress(const char* name) {
#if defined(ARC_HAVE_SDL2)
  if (!name || !SDL_GL_GetCurrentContext()) return 0;
  return reinterpret_cast<uint64_t>(SDL_GL_GetProcAddress(name));
#else
  (void)name;
  return 0;
#endif
}

uint64_t ShimResolveGL(const char* name) {
  if (strcmp(name, "eglGetProcAddress") == 0)
    return reinterpret_cast<uint64_t>(&EglGetProcAddress);
#if defined(ARC_HAVE_SDL2)
  if (strncmp(name, "gl", 2) != 0) return 0;
  // No context, no GL driver to ask. The window is opened before the engine is
  // loaded precisely so this can answer.
  if (!SDL_GL_GetCurrentContext()) return 0;
  return reinterpret_cast<uint64_t>(SDL_GL_GetProcAddress(name));
#else
  (void)name;
  return 0;
#endif
}

}  // namespace arc
