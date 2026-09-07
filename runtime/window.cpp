#include "window.h"

#if defined(ARC_HAVE_SDL2)
#include <SDL.h>
#endif

namespace arc {

#if defined(ARC_HAVE_SDL2)

Window::~Window() { Close(); }

bool Window::Open(const char* title, int width, int height, std::string* err,
                  int major, int minor) {
  if (SDL_Init(SDL_INIT_VIDEO) != 0) {
    if (err) *err = SDL_GetError();
    return false;
  }

  if (major) {
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, major);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, minor);
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

bool Window::MakeCurrent(std::string* err) {
  if (!window_ || !context_) {
    if (err) *err = "no window";
    return false;
  }
  if (SDL_GL_MakeCurrent(static_cast<SDL_Window*>(window_),
                         static_cast<SDL_GLContext>(context_)) != 0) {
    if (err) *err = SDL_GetError();
    return false;
  }
  return true;
}

void Window::ReleaseCurrent() {
  if (window_)
    SDL_GL_MakeCurrent(static_cast<SDL_Window*>(window_), nullptr);
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
      case SDL_MOUSEBUTTONDOWN:
        if (e.button.button == SDL_BUTTON_LEFT) {
          last_x_ = e.button.x;
          last_y_ = e.button.y;
          down_ = true;
          pointers_.push_back({Pointer::Down, last_x_, last_y_, last_x_,
                               last_y_});
        }
        break;
      case SDL_MOUSEBUTTONUP:
        if (e.button.button == SDL_BUTTON_LEFT && down_) {
          down_ = false;
          pointers_.push_back({Pointer::Up, e.button.x, e.button.y, last_x_,
                               last_y_});
          last_x_ = e.button.x;
          last_y_ = e.button.y;
        }
        break;
      case SDL_MOUSEMOTION:
        // Only while held. A drag is the gesture the engine has an entry
        // point for; a hovering cursor is not an event Android can produce,
        // and feeding one in makes a tap out of every pass over the window.
        if (down_) {
          pointers_.push_back({Pointer::Move, e.motion.x, e.motion.y, last_x_,
                               last_y_});
          last_x_ = e.motion.x;
          last_y_ = e.motion.y;
        }
        break;
      default:
        break;
    }
  }
  return open;
}

bool Window::NextPointer(Pointer* out) {
  if (pointers_.empty()) return false;
  *out = pointers_.front();
  pointers_.pop_front();
  return true;
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
bool Window::Open(const char*, int, int, std::string* err, int, int) {
  if (err) *err = "built without SDL2";
  return false;
}
bool Window::MakeCurrent(std::string* err) {
  if (err) *err = "built without SDL2";
  return false;
}
void Window::ReleaseCurrent() {}
bool Window::PumpEvents() { return false; }
bool Window::NextPointer(Pointer*) { return false; }
void Window::Present() {}
void Window::Close() {}
bool Window::TakeResized() { return false; }
std::string Window::Describe() const { return "built without SDL2"; }

#endif

}  // namespace arc
