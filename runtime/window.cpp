#include "window.h"

#if defined(ARC_HAVE_SDL2)
#include <SDL.h>
#endif

namespace arc {

#if defined(ARC_HAVE_SDL2)

Window::~Window() { Close(); }

bool Window::Open(const char* title, int width, int height, std::string* err) {
  if (SDL_Init(SDL_INIT_VIDEO) != 0) {
    if (err) *err = SDL_GetError();
    return false;
  }

  // The engine speaks GLES2 (plus a fixed-function GLESv1_CM tail). Desktop GL
  // exports most of those entry points under identical names, so a compatibility
  // context resolves them directly and avoids dragging in ANGLE. If the ES1
  // calls turn out not to resolve, this is the line to revisit.
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,
                      SDL_GL_CONTEXT_PROFILE_COMPATIBILITY);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);

  SDL_Window* w = SDL_CreateWindow(
      title, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, width, height,
      SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
  if (!w) {
    if (err) *err = SDL_GetError();
    return false;
  }

  SDL_GLContext ctx = SDL_GL_CreateContext(w);
  if (!ctx) {
    if (err) *err = SDL_GetError();
    SDL_DestroyWindow(w);
    return false;
  }

  window_ = w;
  context_ = ctx;
  SDL_GL_GetDrawableSize(w, &width_, &height_);
  return true;
}

bool Window::PumpEvents() {
  SDL_Event e;
  bool open = true;
  while (SDL_PollEvent(&e)) {
    switch (e.type) {
      case SDL_QUIT:
        open = false;
        break;
      case SDL_WINDOWEVENT:
        if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
          SDL_GL_GetDrawableSize(static_cast<SDL_Window*>(window_), &width_,
                                 &height_);
          resized_ = true;
        } else if (e.window.event == SDL_WINDOWEVENT_CLOSE) {
          open = false;
        }
        break;
      case SDL_KEYDOWN:
        if (e.key.keysym.sym == SDLK_ESCAPE) open = false;
        break;
      default:
        // Pointer and key events are translated where they are consumed --
        // by the JNI bridge that calls pointerPressed/keyPressed. Adding a
        // translation layer here before that exists would have no reader.
        break;
    }
  }
  return open;
}

void Window::Present() {
  if (window_) SDL_GL_SwapWindow(static_cast<SDL_Window*>(window_));
}

void Window::Close() {
  if (context_) {
    SDL_GL_DeleteContext(static_cast<SDL_GLContext>(context_));
    context_ = nullptr;
  }
  if (window_) {
    SDL_DestroyWindow(static_cast<SDL_Window*>(window_));
    window_ = nullptr;
    SDL_Quit();
  }
}

bool Window::TakeResized() {
  bool was = resized_;
  resized_ = false;
  return was;
}

std::string Window::Describe() const {
  if (!context_) return "no context";
  int major = 0, minor = 0, profile = 0;
  SDL_GL_GetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, &major);
  SDL_GL_GetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, &minor);
  SDL_GL_GetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, &profile);
  const char* kind = profile == SDL_GL_CONTEXT_PROFILE_ES     ? "ES"
                     : profile == SDL_GL_CONTEXT_PROFILE_CORE ? "core"
                                                              : "compatibility";
  return "GL " + std::to_string(major) + "." + std::to_string(minor) + " " +
         kind;
}

#else  // no SDL2

Window::~Window() = default;
bool Window::Open(const char*, int, int, std::string* err) {
  if (err) *err = "built without SDL2";
  return false;
}
bool Window::PumpEvents() { return false; }
void Window::Present() {}
void Window::Close() {}
bool Window::TakeResized() { return false; }
std::string Window::Describe() const { return "built without SDL2"; }

#endif

}  // namespace arc
