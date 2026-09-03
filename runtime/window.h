// The desktop stand-in for Android's GLSurfaceView.
//
// On Android, Java owns the window and the EGL context and calls into the
// engine; the engine imports no `egl*` symbol at all. That division is what
// makes this straightforward: the host creates a window and a GL context, and
// the engine only ever issues GL calls into whatever is current.
//
// Creating the context before loading the engine is not incidental ordering.
// The engine's 50 GL imports bind through `SDL_GL_GetProcAddress`, which needs
// a current context to answer, so the window has to exist first -- exactly as
// it does on Android.
#pragma once

#include <string>

namespace arc {

class Window {
 public:
  ~Window();

  bool Open(const char* title, int width, int height, std::string* err);

  // Drains the event queue. Returns false once the user has asked to close,
  // which is the host's cue to call the engine's destroy path.
  bool PumpEvents();

  void Present();
  void Close();

  int width() const { return width_; }
  int height() const { return height_; }

  // True when the drawable was resized since the last call, so the host knows
  // to forward it to OGLESResize.
  bool TakeResized();

  // Human-readable description of the context we actually got.
  std::string Describe() const;

 private:
  void* window_ = nullptr;
  void* context_ = nullptr;
  int width_ = 0;
  int height_ = 0;
  bool resized_ = false;
};

}  // namespace arc
