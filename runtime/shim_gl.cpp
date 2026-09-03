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

uint64_t ShimResolveGL(const char* name) {
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
