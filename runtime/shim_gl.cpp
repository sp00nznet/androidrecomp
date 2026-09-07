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
//
// Two entry points are not pass-through, because the *language* differs where
// the API does not: an engine written for GLES2 hands the driver GLSL ES, and
// desktop GLSL rejects it over precision qualifiers alone. A rejected shader
// does not raise anything -- the program links to nothing, every uniform
// location comes back as -1, and the frame draws a black screen with a full
// set of draw calls behind it. So shader source is translated on the way
// through, and a compile or link that still fails says so.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "arm64_context.h"
#include "shim.h"

#if defined(ARC_HAVE_SDL2)
#include <SDL.h>
#endif

namespace arc {

#if defined(ARC_HAVE_SDL2)
namespace {

using GLuint = unsigned;
using GLint = int;
using GLsizei = int;
using GLenum = unsigned;
using GLchar = char;

constexpr GLenum kCompileStatus = 0x8B81;
constexpr GLenum kLinkStatus = 0x8B82;
constexpr GLenum kInfoLogLength = 0x8B84;

void* Real(const char* name) { return SDL_GL_GetProcAddress(name); }

// GLSL ES 1.00 into GLSL 1.20, which is what a 2.1 context accepts.
//
// Only two things actually differ for shaders of this vintage: the version
// line, and precision. `precision mediump float;` is a statement desktop GLSL
// has no grammar for, and `lowp`/`mediump`/`highp` appear inline on
// declarations -- so the statements are dropped and the qualifiers defined
// away. Everything else (attribute, varying, texture2D, gl_FragColor) means
// the same in both.
std::string ToDesktopGlsl(const std::string& in) {
  std::string out =
      "#version 120\n#define lowp\n#define mediump\n#define highp\n";
  size_t i = 0;
  while (i < in.size()) {
    size_t end = in.find('\n', i);
    if (end == std::string::npos) end = in.size();
    const std::string line = in.substr(i, end - i);
    size_t first = line.find_first_not_of(" \t\r");
    const bool version =
        first != std::string::npos && line.compare(first, 8, "#version") == 0;
    const bool precision =
        first != std::string::npos && line.compare(first, 9, "precision") == 0;
    // Both are replaced by a blank line rather than deleted, so a compiler
    // error still names the line the author would find in the file.
    out += (version || precision) ? "" : line;
    out += '\n';
    i = end + 1;
  }
  return out;
}

std::string InfoLog(GLuint object, bool is_program) {
  auto get_iv = reinterpret_cast<void (*)(GLuint, GLenum, GLint*)>(
      Real(is_program ? "glGetProgramiv" : "glGetShaderiv"));
  auto get_log = reinterpret_cast<void (*)(GLuint, GLsizei, GLsizei*, GLchar*)>(
      Real(is_program ? "glGetProgramInfoLog" : "glGetShaderInfoLog"));
  if (!get_iv || !get_log) return {};
  GLint n = 0;
  get_iv(object, kInfoLogLength, &n);
  if (n <= 1) return {};
  std::string log(static_cast<size_t>(n), '\0');
  GLsizei written = 0;
  get_log(object, n, &written, &log[0]);
  log.resize(static_cast<size_t>(written));
  return log;
}

void ShaderSource(GLuint shader, GLsizei count, const GLchar* const* strings,
                  const GLint* lengths) {
  std::string joined;
  for (GLsizei i = 0; i < count; ++i) {
    if (!strings || !strings[i]) continue;
    if (lengths && lengths[i] >= 0)
      joined.append(strings[i], static_cast<size_t>(lengths[i]));
    else
      joined.append(strings[i]);
  }
  std::string translated = ToDesktopGlsl(joined);
  // Two diagnostics, off unless asked for, that split the fragment stage in
  // half. ARC_GL_FLAT=1 paints every fragment solid red: an empty frame with
  // that on means the geometry never arrives, and neither the texture nor the
  // blend state is worth looking at. ARC_GL_FLAT=tex paints the diffuse
  // texture opaque: an empty frame with *that* on means the sampler, not the
  // colour it is multiplied by.
  const char* probe = getenv("ARC_GL_FLAT");
  if (probe && translated.find("gl_FragColor") != std::string::npos)
    translated = probe[0] == 't'
                     ? "#version 120\n"
                       "varying vec2 v_texCoord;\n"
                       "uniform sampler2D diffuseTexture;\n"
                       "void main(){gl_FragColor="
                       "vec4(texture2D(diffuseTexture,v_texCoord).rgb,1.);}\n"
                     : "#version 120\n"
                       "void main(){gl_FragColor=vec4(1.,0.,0.,1.);}\n";
  if (getenv("ARC_TRACE_SHADERS"))
    fprintf(stderr, "[shader %u]\n%s\n", shader, translated.c_str());
  const char* p = translated.c_str();
  const GLint n = static_cast<GLint>(translated.size());
  auto real = reinterpret_cast<void (*)(GLuint, GLsizei, const GLchar* const*,
                                        const GLint*)>(Real("glShaderSource"));
  if (real) real(shader, 1, &p, &n);
}

void CompileShader(GLuint shader) {
  auto real = reinterpret_cast<void (*)(GLuint)>(Real("glCompileShader"));
  if (real) real(shader);
  auto get_iv =
      reinterpret_cast<void (*)(GLuint, GLenum, GLint*)>(Real("glGetShaderiv"));
  GLint ok = 1;
  if (get_iv) get_iv(shader, kCompileStatus, &ok);
  if (!ok)
    fprintf(stderr, "shader %u failed to compile:\n%s\n", shader,
            InfoLog(shader, false).c_str());
}

void LinkProgram(GLuint program) {
  auto real = reinterpret_cast<void (*)(GLuint)>(Real("glLinkProgram"));
  if (real) real(program);
  auto get_iv = reinterpret_cast<void (*)(GLuint, GLenum, GLint*)>(
      Real("glGetProgramiv"));
  GLint ok = 1;
  if (get_iv) get_iv(program, kLinkStatus, &ok);
  if (!ok)
    fprintf(stderr, "program %u failed to link:\n%s\n", program,
            InfoLog(program, true).c_str());
}

// A draw that the driver rejects still counts as a draw everywhere else: the
// call returns, the frame completes, and the screen stays the colour of the
// clear. glGetError is the only place that difference is visible, so the first
// few are reported rather than left to be inferred from an empty window.
void DrawElements(GLenum mode, GLsizei count, GLenum type, const void* indices) {
  auto real = reinterpret_cast<void (*)(GLenum, GLsizei, GLenum, const void*)>(
      Real("glDrawElements"));
  auto get_error = reinterpret_cast<GLenum (*)()>(Real("glGetError"));
  static int left = 8;
  if (left > 0 && get_error) while (get_error()) {}
  if (real) real(mode, count, type, indices);
  if (left <= 0) return;
  const GLenum e = get_error ? get_error() : 0;
  if (e) {
    --left;
    fprintf(stderr, "glDrawElements(mode=%#x count=%d) -> GL error %#x\n", mode,
            count, e);
  }
}

// The same argument for textures. A GLES-only format is an enum desktop GL
// does not know, and the call that carries it leaves the texture at whatever
// it was -- which is the transparent black a fresh texture starts as, drawn
// without complaint over every frame after.
void TexImage2D(GLenum target, GLint level, GLint internal, GLsizei w,
                GLsizei h, GLint border, GLenum format, GLenum type,
                const void* pixels) {
  auto real = reinterpret_cast<void (*)(GLenum, GLint, GLint, GLsizei, GLsizei,
                                        GLint, GLenum, GLenum, const void*)>(
      Real("glTexImage2D"));
  auto get_error = reinterpret_cast<GLenum (*)()>(Real("glGetError"));
  static int left = 8;
  // Drained first, so what comes back afterwards belongs to this call and not
  // to whatever the engine did before it.
  if (left > 0 && get_error) while (get_error()) {}
  if (real)
    real(target, level, internal, w, h, border, format, type, pixels);
  if (getenv("ARC_TRACE_GL")) {
    auto get_iv = reinterpret_cast<void (*)(GLenum, GLint*)>(
        Real("glGetIntegerv"));
    GLint bound = -1;
    if (get_iv) get_iv(0x8069 /* GL_TEXTURE_BINDING_2D */, &bound);
    fprintf(stderr, "glTexImage2D tex=%d level=%d %dx%d internal=%#x type=%#x",
            bound, level, w, h, internal, type);
    // The first bytes of the image. All-zero here and the decode is the
    // problem; anything else and the sampler state is.
    if (pixels) {
      const auto* p = static_cast<const unsigned char*>(pixels);
      fprintf(stderr, " bytes");
      for (int i = 0; i < 12; ++i) fprintf(stderr, " %02x", p[i]);
    } else {
      fprintf(stderr, " empty");
    }
    fprintf(stderr, "\n");
  }
  if (left <= 0) return;
  const GLenum e = get_error ? get_error() : 0;
  if (e) {
    --left;
    fprintf(stderr,
            "glTexImage2D(%dx%d internal=%#x format=%#x type=%#x) -> GL error "
            "%#x\n", w, h, internal, format, type, e);
  }
}

// The transform every draw is placed by. A quad that is drawn with a matrix of
// zeroes, or of NaNs, produces exactly the frame a quad that is never drawn
// does -- and the matrix is the one thing here computed by lifted arithmetic
// rather than handed straight through.
void UniformMatrix4fv(GLint location, GLsizei count, unsigned char transpose,
                      const float* v) {
  auto real = reinterpret_cast<void (*)(GLint, GLsizei, unsigned char,
                                        const float*)>(
      Real("glUniformMatrix4fv"));
  if (real) real(location, count, transpose, v);
  static int left = 4;
  if (!getenv("ARC_TRACE_GL") || left <= 0 || !v || location < 0) return;
  --left;
  fprintf(stderr, "glUniformMatrix4fv loc=%d\n", location);
  for (int r = 0; r < 4; ++r)
    fprintf(stderr, "  % .4f % .4f % .4f % .4f\n", v[r * 4], v[r * 4 + 1],
            v[r * 4 + 2], v[r * 4 + 3]);
}

// Desktop GL keeps generic attribute 0 aliased to the fixed-function vertex
// array, and a compatibility context generates no primitives at all unless
// array 0 is enabled. GLES has no such rule, so an engine is free to start its
// attributes at 1 -- which this one does: position at 1, uvs at 2, colour at
// 3. Every draw then sets correct state, raises no error, and produces nothing.
//
// So the indices are shifted down by one on the way through, consistently for
// the binding and for the arrays. Index 0 arriving from the guest would have
// nowhere to go; it never does here, and if it ever did the shift would be the
// wrong answer rather than a silent one.
// ponytail: a shift, not a mapping table. A title that uses 0 and 1 together
// needs the table.
GLuint ShiftAttrib(GLuint index) {
  if (index) return index - 1;
  static bool said = false;
  if (!said) {
    said = true;
    fprintf(stderr, "[gl] the engine used attribute 0; not shifting it\n");
  }
  return 0;
}

void BindAttribLocation(GLuint program, GLuint index, const GLchar* name) {
  auto real = reinterpret_cast<void (*)(GLuint, GLuint, const GLchar*)>(
      Real("glBindAttribLocation"));
  if (real) real(program, ShiftAttrib(index), name);
}

void VertexAttribPointer(GLuint index, GLint size, GLenum type,
                         unsigned char normalized, GLsizei stride,
                         const void* pointer) {
  auto real = reinterpret_cast<void (*)(GLuint, GLint, GLenum, unsigned char,
                                        GLsizei, const void*)>(
      Real("glVertexAttribPointer"));
  if (real)
    real(ShiftAttrib(index), size, type, normalized, stride, pointer);
}

void EnableVertexAttribArray(GLuint index) {
  auto real =
      reinterpret_cast<void (*)(GLuint)>(Real("glEnableVertexAttribArray"));
  if (real) real(ShiftAttrib(index));
}

void DisableVertexAttribArray(GLuint index) {
  auto real =
      reinterpret_cast<void (*)(GLuint)>(Real("glDisableVertexAttribArray"));
  if (real) real(ShiftAttrib(index));
}

// A deliberate diagnostic, off unless asked for: clear to a colour nothing in
// the game would produce. A capture that comes back that colour says the
// context, the buffer and the readback are all sound and the draws are what is
// missing; a capture that comes back black says to stop looking at the draws.
void Clear(unsigned mask) {
  static int said = 0;
  if (!said) {
    said = 1;
    fprintf(stderr, "[gl] first glClear mask=%#x real=%p tint=%s\n", mask,
            Real("glClear"), getenv("ARC_GL_TINT") ? "on" : "off");
  }
  if (getenv("ARC_GL_TINT")) {
    auto cc = reinterpret_cast<void (*)(float, float, float, float)>(
        Real("glClearColor"));
    if (cc) cc(0.4f, 0.0f, 0.5f, 1.0f);
  }
  auto real = reinterpret_cast<void (*)(unsigned)>(Real("glClear"));
  if (real) real(mask);
}

// Sampler state, which decides whether a complete-looking texture samples as
// itself or as black: a mipmap minification filter with no mip levels makes a
// texture incomplete, and an incomplete texture reads (0,0,0,1) everywhere.
void TexParameterf(GLenum target, GLenum pname, float value) {
  auto real = reinterpret_cast<void (*)(GLenum, GLenum, float)>(
      Real("glTexParameterf"));
  if (real) real(target, pname, value);
  if (!getenv("ARC_TRACE_GL")) return;
  auto get_iv =
      reinterpret_cast<void (*)(GLenum, GLint*)>(Real("glGetIntegerv"));
  GLint bound = -1;
  if (get_iv) get_iv(0x8069, &bound);
  fprintf(stderr, "glTexParameterf tex=%d pname=%#x value=%#x\n", bound, pname,
          static_cast<unsigned>(value));
}

// --- the ones that take a float ------------------------------------------
//
// The dispatcher's thunk carries twelve integers and nothing in v0-v7, so a
// GL call whose argument is a float by value arrived with whatever happened to
// be in the integer slot. glTexParameterf is where that showed: every
// parameter was set to 0, which is not a valid enum, so every set was rejected
// and every texture kept the default GL_NEAREST_MIPMAP_LINEAR. With no mip
// levels that leaves the texture incomplete, and an incomplete texture samples
// as black -- a whole frame of correct draws, in black, with no GL error.
//
// These four take the context instead and read v0 onward themselves.
void CtxClearColor(Arm64Ctx* c) {
  auto real = reinterpret_cast<void (*)(float, float, float, float)>(
      Real("glClearColor"));
  if (real)
    real(ARC_S_R(c, 0), ARC_S_R(c, 1), ARC_S_R(c, 2), ARC_S_R(c, 3));
}

void CtxTexParameterf(Arm64Ctx* c) {
  auto real = reinterpret_cast<void (*)(GLenum, GLenum, float)>(
      Real("glTexParameterf"));
  if (real)
    real(static_cast<GLenum>(c->x[0]), static_cast<GLenum>(c->x[1]),
         ARC_S_R(c, 0));
}

void CtxLineWidth(Arm64Ctx* c) {
  auto real = reinterpret_cast<void (*)(float)>(Real("glLineWidth"));
  if (real) real(ARC_S_R(c, 0));
}

void CtxUniform1f(Arm64Ctx* c) {
  auto real = reinterpret_cast<void (*)(GLint, float)>(Real("glUniform1f"));
  if (real) real(static_cast<GLint>(c->x[0]), ARC_S_R(c, 0));
}

struct CtxEntry {
  const char* name;
  ArcCtxFn fn;
};
const CtxEntry kCtxTable[] = {
    {"glClearColor", CtxClearColor},
    {"glTexParameterf", CtxTexParameterf},
    {"glLineWidth", CtxLineWidth},
    {"glUniform1f", CtxUniform1f},
};

}  // namespace
#endif

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
  // The same two names are intercepted here as in the import table: an engine
  // that resolves them this way instead would otherwise reach the driver with
  // GLSL ES in hand.
  if (uint64_t a = ShimResolveGL(name)) return ShimHandOut(a, name);
  // Announced to the dispatcher, because the guest is about to branch to it.
  // An import is announced when it binds at load time; a pointer produced this
  // late has no such moment, and without one the branch lands on host code the
  // dispatcher has never heard of and is reported as going nowhere.
  return ShimHandOut(reinterpret_cast<uint64_t>(SDL_GL_GetProcAddress(name)),
                     name);
#else
  (void)name;
  return 0;
#endif
}

void ShimRegisterGL() {
#if defined(ARC_HAVE_SDL2)
  for (const CtxEntry& e : kCtxTable)
    arc_register_ctx_native(reinterpret_cast<uint64_t>(e.fn), e.name, e.fn);
#endif
}

uint64_t ShimResolveGL(const char* name) {
  if (strcmp(name, "eglGetProcAddress") == 0)
    return reinterpret_cast<uint64_t>(&EglGetProcAddress);
#if defined(ARC_HAVE_SDL2)
  if (strncmp(name, "gl", 2) != 0) return 0;
  // Before the context check: these are ours, not the driver's.
  for (const CtxEntry& e : kCtxTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  // No context, no GL driver to ask. The window is opened before the engine is
  // loaded precisely so this can answer.
  if (!SDL_GL_GetCurrentContext()) return 0;
  if (strcmp(name, "glShaderSource") == 0)
    return reinterpret_cast<uint64_t>(&ShaderSource);
  if (strcmp(name, "glCompileShader") == 0)
    return reinterpret_cast<uint64_t>(&CompileShader);
  if (strcmp(name, "glLinkProgram") == 0)
    return reinterpret_cast<uint64_t>(&LinkProgram);
  if (strcmp(name, "glDrawElements") == 0)
    return reinterpret_cast<uint64_t>(&DrawElements);
  if (strcmp(name, "glTexImage2D") == 0)
    return reinterpret_cast<uint64_t>(&TexImage2D);
  if (strcmp(name, "glTexParameterf") == 0)
    return reinterpret_cast<uint64_t>(&TexParameterf);
  if (strcmp(name, "glUniformMatrix4fv") == 0)
    return reinterpret_cast<uint64_t>(&UniformMatrix4fv);
  if (strcmp(name, "glClear") == 0)
    return reinterpret_cast<uint64_t>(&Clear);
  if (strcmp(name, "glBindAttribLocation") == 0)
    return reinterpret_cast<uint64_t>(&BindAttribLocation);
  if (strcmp(name, "glVertexAttribPointer") == 0)
    return reinterpret_cast<uint64_t>(&VertexAttribPointer);
  if (strcmp(name, "glEnableVertexAttribArray") == 0)
    return reinterpret_cast<uint64_t>(&EnableVertexAttribArray);
  if (strcmp(name, "glDisableVertexAttribArray") == 0)
    return reinterpret_cast<uint64_t>(&DisableVertexAttribArray);
  return reinterpret_cast<uint64_t>(SDL_GL_GetProcAddress(name));
#else
  (void)name;
  return 0;
#endif
}

}  // namespace arc
