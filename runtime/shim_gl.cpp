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
#include <algorithm>
#include <map>
#include <mutex>
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
// A draw whose indices are an offset, with nothing for them to be an offset
// into.
//
// `indices` means two different things depending on GL state: a pointer into
// client memory when no element array buffer is bound, and a byte offset into
// the bound buffer when one is. The engine binds a buffer and passes an
// offset -- 0xc, say -- so if the binding is not there when the draw arrives
// the driver reads address 0xc and takes the process with it. That is a fault
// inside the driver, attributed to it, with nothing to say the engine's own
// state was the problem.
//
// The draw cannot be issued either way. Skipping it costs one draw call;
// issuing it costs the run.
//
// ponytail: skips rather than fixing whatever loses the binding. The report
// says how many, because a frame that skips half its draws is a frame worth
// looking at rather than a frame that rendered.
// The last transform handed to the shader, kept so a draw can name it.
float g_last_matrix[16];
extern float g_last_uniform4[4];

// Which texture the draws are actually using.
//
// A sprite that covers the screen is either drawn too many times or drawn with
// the wrong picture, and those look identical from outside. Counting draws per
// texture separates them: one texture with tens of thousands of draws against
// a handful each for everything else is not a sprite that is too big, it is a
// sprite that is being drawn everywhere. Dumping that texture says which
// picture it is, which is the part no amount of reasoning about the save file
// will tell you.
//
// ARC_GL_CENSUS=<n> reports after n frames and dumps the busiest texture next
// to the report, as a PPM.
struct TexFacts {
  int width = 0;
  int height = 0;
  long draws = 0;
};
std::map<unsigned, TexFacts> g_textures;
std::mutex g_texture_lock;

int CensusAfter() {
  static const int after = [] {
    const char* n = getenv("ARC_GL_CENSUS");
    return n ? atoi(n) : 0;
  }();
  return after;
}

unsigned BoundTexture() {
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  if (!get_int) return 0;
  GLint id = 0;
  get_int(0x8069 /* GL_TEXTURE_BINDING_2D */, &id);
  return static_cast<unsigned>(id);
}

// Leave out every draw that uses a named texture, so that what disappears
// says what that texture was drawing. ARC_GL_SKIP_TEX=<id>[,<id>...].
bool TextureIsSkipped(unsigned id) {
  static const char* const list = getenv("ARC_GL_SKIP_TEX");
  if (!list || !*list || !id) return false;
  for (const char* p = list; *p;) {
    if (static_cast<unsigned>(strtoul(p, nullptr, 10)) == id) return true;
    const char* comma = strchr(p, ',');
    if (!comma) break;
    p = comma + 1;
  }
  return false;
}

// One frame's draws, in order, with the state that decides what covers what.
//
// A layer that should be behind everything and is in front of it looks exactly
// like a layer drawn too many times, until you see where in the frame it goes.
// ARC_GL_TRACE_FRAME=<n> logs frame n: the order, the texture, and whether
// depth testing and writing were on -- which is what separates "drawn last" 
// from "drawn first and not covered".
int TraceFrame() {
  static const int which = [] {
    const char* n = getenv("ARC_GL_TRACE_FRAME");
    return n ? atoi(n) : 0;
  }();
  return which;
}

int g_frame = 0;

void TraceThisDraw(unsigned texture, int count) {
  if (!TraceFrame() || g_frame != TraceFrame()) return;
  auto is_on = reinterpret_cast<unsigned char (*)(GLenum)>(Real("glIsEnabled"));
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  static int n = 0;
  GLint mask = -1, func = -1, src = -1, dst = -1, prog = -1;
  if (get_int) {
    get_int(0x0B72 /* GL_DEPTH_WRITEMASK */, &mask);
    get_int(0x0B74 /* GL_DEPTH_FUNC */, &func);
    // How the sprite is combined with what is already there. A layer that is
    // meant to darken the ground and a layer that is meant to paint over it
    // differ only here, and getting it wrong turns a soft shadow into an
    // opaque shape.
    get_int(0x80C9 /* GL_BLEND_SRC_RGB */, &src);
    get_int(0x80C8 /* GL_BLEND_DST_RGB */, &dst);
    get_int(0x8B8D /* GL_CURRENT_PROGRAM */, &prog);
  }
  fprintf(stderr, "[gl]   matrix % .3f % .3f % .3f % .3f | % .3f % .3f"
                  " % .3f % .3f\n",
          g_last_matrix[0], g_last_matrix[1], g_last_matrix[2],
          g_last_matrix[3], g_last_matrix[12], g_last_matrix[13],
          g_last_matrix[14], g_last_matrix[15]);
  fprintf(stderr,
          "[gl] frame %d draw %-5d texture %-4u indices %-6d prog %-3d"
          " diffuse %.3f %.3f %.3f %.3f"
          " depth=%s write=%d func=%#x blend=%s src=%#x dst=%#x\n",
          g_frame, n++, texture, count, prog, g_last_uniform4[0],
          g_last_uniform4[1], g_last_uniform4[2], g_last_uniform4[3],
          is_on && is_on(0x0B71 /* GL_DEPTH_TEST */) ? "on" : "off", mask, func,
          is_on && is_on(0x0BE2 /* GL_BLEND */) ? "on" : "off", src, dst);
}

// Which guest code issued a draw. The census says which texture a layer uses
// and the trace says where in the frame it goes; neither says who asked for
// it. The frame ring does -- it holds the guest functions entered, most
// recent first, so reading it at the moment of a draw names the caller.
// ARC_GL_WHO=<texture> prints it once for that texture.
void WhoDrew(unsigned texture) {
  static const char* const want = getenv("ARC_GL_WHO");
  if (!want) return;
  if (texture != static_cast<unsigned>(atoi(want))) return;
  static bool said = false;
  if (said) return;
  said = true;
  fprintf(stderr, "[gl] texture %u is drawn from, most recent first:\n",
          texture);
  const size_t n = arc_frame_count();
  for (size_t i = 0; i < n && i < 24; ++i)
    fprintf(stderr, "[gl]   %#llx\n",
            static_cast<unsigned long long>(arc_frame_at(i)));
}

// The geometry a draw is about to use, read back through its own indices.
//
// Everything else about this layer has checked out -- the sprite, its alpha,
// the shader, the blend mode, the transform -- which leaves two possibilities
// that look identical on screen: the quads are in the wrong places, or they
// are in the right places and should not have been emitted at all. The
// positions tell them apart, but only if they are the positions this draw
// actually selects: reading the front of the buffer answers about whatever
// was packed there first, which is a different question.
//
// ARC_GL_VERTS=<texture> prints the first quad of the first two draws.
void ShowVertices(unsigned texture, GLsizei count, GLenum type,
                  const void* indices) {
  static const char* const want = getenv("ARC_GL_VERTS");
  if (!want || texture != static_cast<unsigned>(atoi(want))) return;
  // One line per draw rather than one per vertex: the layout of a layer over
  // the map is the thing in question, and that is a map of first vertices.
  static const bool spread = getenv("ARC_GL_SPREAD") != nullptr;
  static int left = spread ? 3 : 2;
  if (left <= 0 || count < 3) return;
  auto get_attr = reinterpret_cast<void (*)(GLuint, GLenum, GLint*)>(
      Real("glGetVertexAttribiv"));
  auto get_attr_ptr = reinterpret_cast<void (*)(GLuint, GLenum, void**)>(
      Real("glGetVertexAttribPointerv"));
  auto get_sub = reinterpret_cast<void (*)(GLenum, intptr_t, intptr_t, void*)>(
      Real("glGetBufferSubData"));
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  if (!get_attr || !get_attr_ptr || !get_sub || !get_int) return;
  --left;

  // Which host attribute holds the position is not obvious: the shim shifts
  // the guest's attribute numbers up by one for desktop GL, so guest 1 is
  // host 2. Rather than assume, every enabled attribute is printed and the
  // one carrying world coordinates identifies itself.
  GLint ibuf = 0;
  get_int(0x8895 /* ELEMENT_ARRAY_BUFFER_BINDING */, &ibuf);
  struct Attr { GLint size, stride, buf; void* base; };
  Attr attrs[8] = {};
  for (int a = 0; a < 8; ++a) {
    GLint on = 0;
    get_attr(static_cast<GLuint>(a), 0x8622 /* ARRAY_ENABLED */, &on);
    if (!on) continue;
    get_attr(static_cast<GLuint>(a), 0x8623, &attrs[a].size);
    get_attr(static_cast<GLuint>(a), 0x8624, &attrs[a].stride);
    get_attr(static_cast<GLuint>(a), 0x889F, &attrs[a].buf);
    get_attr_ptr(static_cast<GLuint>(a), 0x8645, &attrs[a].base);
  }
  GLint size = attrs[1].size, stride = attrs[1].stride, vbuf = attrs[1].buf;
  void* base = attrs[1].base;
  const int wide = type == 0x1405 ? 4 : (type == 0x1403 ? 2 : 1);

  // The indices, from the bound element buffer or from client memory.
  // In spread mode, one vertex per quad across the whole draw: the shape of
  // the layer -- a grid at the land pitch, or a scatter -- is the thing in
  // question, and one sample per batch cannot show it.
  const int take = spread ? count : (count < 6 ? count : 6);
  std::vector<unsigned char> idx(static_cast<size_t>(take) * wide, 0);
  if (ibuf)
    get_sub(0x8893 /* GL_ELEMENT_ARRAY_BUFFER */,
            reinterpret_cast<intptr_t>(indices),
            static_cast<intptr_t>(idx.size()), idx.data());
  else if (indices)
    memcpy(idx.data(), indices, idx.size());
  else
    return;

  if (!spread)
    fprintf(stderr,
            "[gl] texture %u: size=%d stride=%d vbuf=%d ibuf=%d count=%d\n",
            texture, size, stride, vbuf, ibuf, count);
  for (int k = 0; k < take; k += (spread ? 6 : 1)) {
    unsigned long v = 0;
    if (wide == 4) { unsigned t; memcpy(&t, idx.data() + k * 4, 4); v = t; }
    else if (wide == 2) { unsigned short t; memcpy(&t, idx.data() + k * 2, 2); v = t; }
    else v = idx[k];
    float xyz[4] = {0, 0, 0, 0};
    const size_t at = static_cast<size_t>(v) * static_cast<size_t>(stride);
    const size_t n = sizeof(float) * (size > 4 ? 4 : size);
    if (vbuf) {
      get_sub(0x8892 /* GL_ARRAY_BUFFER */,
              static_cast<intptr_t>(reinterpret_cast<uintptr_t>(base) + at),
              static_cast<intptr_t>(n), xyz);
    } else if (base) {
      memcpy(xyz, static_cast<const unsigned char*>(base) + at, n);
    }
    (void)xyz;
    if (spread) {
      float f[4] = {0, 0, 0, 0};
      const size_t off = static_cast<size_t>(v) *
                         static_cast<size_t>(attrs[0].stride);
      if (attrs[0].buf)
        get_sub(0x8892,
                static_cast<intptr_t>(
                    reinterpret_cast<uintptr_t>(attrs[0].base) + off),
                static_cast<intptr_t>(12), f);
      else if (attrs[0].base)
        memcpy(f, static_cast<const unsigned char*>(attrs[0].base) + off, 12);
      // The uv as well as the position, and the offset the indices start
      // at: five draws that share an origin are either the same geometry
      // drawn five times or five different sprites on it, and only the uv
      // and the index offset tell them apart.
      float uv[2] = {0, 0};
      if (attrs[1].stride) {
        const size_t uoff = static_cast<size_t>(v) *
                            static_cast<size_t>(attrs[1].stride);
        if (attrs[1].buf)
          get_sub(0x8892,
                  static_cast<intptr_t>(
                      reinterpret_cast<uintptr_t>(attrs[1].base) + uoff),
                  static_cast<intptr_t>(8), uv);
        else if (attrs[1].base)
          memcpy(uv, static_cast<const unsigned char*>(attrs[1].base) + uoff, 8);
      }
      // And the per-vertex colour, read as bytes. It is almost always
      // GL_UNSIGNED_BYTE and reading it as floats gives nonsense -- which is
      // what hid the alpha, the one number that decides whether drawing the
      // same batch several times is harmless or turns a decal opaque.
      unsigned char col[4] = {0, 0, 0, 0};
      if (attrs[2].stride) {
        const size_t coff = static_cast<size_t>(v) *
                            static_cast<size_t>(attrs[2].stride);
        if (attrs[2].buf)
          get_sub(0x8892,
                  static_cast<intptr_t>(
                      reinterpret_cast<uintptr_t>(attrs[2].base) + coff),
                  static_cast<intptr_t>(4), col);
        else if (attrs[2].base)
          memcpy(col, static_cast<const unsigned char*>(attrs[2].base) + coff, 4);
      }
      fprintf(stderr,
              "[spread] %d % .1f % .1f uv % .4f % .4f rgba %3d %3d %3d %3d"
              " vbuf %d at %llu\n",
              count, f[0], f[1], uv[0], uv[1], col[0], col[1], col[2], col[3],
              attrs[0].buf,
              static_cast<unsigned long long>(
                  reinterpret_cast<uintptr_t>(indices)));
      continue;
    }
    fprintf(stderr, "[gl]   index %-6lu\n", v);
    for (int a = 0; a < 8; ++a) {
      if (!attrs[a].stride) continue;
      float f[4] = {0, 0, 0, 0};
      const size_t off = static_cast<size_t>(v) *
                         static_cast<size_t>(attrs[a].stride);
      const size_t n = sizeof(float) *
                       (attrs[a].size > 4 ? 4 : attrs[a].size);
      if (attrs[a].buf)
        get_sub(0x8892,
                static_cast<intptr_t>(
                    reinterpret_cast<uintptr_t>(attrs[a].base) + off),
                static_cast<intptr_t>(n), f);
      else if (attrs[a].base)
        memcpy(f, static_cast<const unsigned char*>(attrs[a].base) + off, n);
      fprintf(stderr, "[gl]     attr %d size %d:  % .3f % .3f % .3f % .3f\n",
              a, attrs[a].size, f[0], f[1], f[2], f[3]);
    }
  }
}

void NoteDraw() {
  if (!CensusAfter()) return;
  const unsigned id = BoundTexture();
  std::lock_guard<std::mutex> held(g_texture_lock);
  ++g_textures[id].draws;
}

void NoteTexture(int w, int h) {
  if (!CensusAfter()) return;
  const unsigned id = BoundTexture();
  std::lock_guard<std::mutex> held(g_texture_lock);
  TexFacts& f = g_textures[id];
  if (w > f.width) f.width = w;
  if (h > f.height) f.height = h;
}

void DumpTexture(unsigned id, int w, int h) {
  auto bind = reinterpret_cast<void (*)(GLenum, unsigned)>(
      Real("glBindTexture"));
  auto get_image = reinterpret_cast<void (*)(GLenum, GLint, GLenum, GLenum,
                                             void*)>(Real("glGetTexImage"));
  if (!bind || !get_image || w <= 0 || h <= 0) {
    fprintf(stderr, "[gl] cannot read texture %u back\n", id);
    return;
  }
  const unsigned was = BoundTexture();
  std::vector<unsigned char> rgba(static_cast<size_t>(w) * h * 4, 0);
  bind(0x0DE1 /* GL_TEXTURE_2D */, id);
  get_image(0x0DE1, 0, 0x1908 /* GL_RGBA */, 0x1401 /* GL_UNSIGNED_BYTE */,
            rgba.data());
  bind(0x0DE1, was);
  char path[256];
  snprintf(path, sizeof path, "arc_texture_%u.ppm", id);
  FILE* out = fopen(path, "wb");
  if (!out) return;
  fprintf(out, "P6\n%d %d\n255\n", w, h);
  // Flattened onto white, because the interesting part of a sprite sheet is
  // its shapes and those are invisible against an unpainted alpha channel.
  for (size_t i = 0; i + 3 < rgba.size(); i += 4) {
    const unsigned a = rgba[i + 3];
    for (int k = 0; k < 3; ++k) {
      const unsigned v = (rgba[i + k] * a + 255u * (255u - a)) / 255u;
      fputc(static_cast<int>(v), out);
    }
  }
  fclose(out);
  // And the alpha on its own. Flattening onto white above makes a sprite
  // legible but hides the channel that decides whether it is a soft decal or
  // an opaque shape -- which is exactly the question when a layer is visible
  // and should not be.
  snprintf(path, sizeof path, "arc_texture_%u_alpha.ppm", id);
  if (FILE* a = fopen(path, "wb")) {
    fprintf(a, "P6\n%d %d\n255\n", w, h);
    for (size_t i = 0; i + 3 < rgba.size(); i += 4) {
      const int v = rgba[i + 3];
      fputc(v, a); fputc(v, a); fputc(v, a);
    }
    fclose(a);
  }
  fprintf(stderr, "[gl] wrote %s (%dx%d) and its alpha\n", path, w, h);
}

void ReportCensus() {
  std::vector<std::pair<unsigned, TexFacts>> all;
  {
    std::lock_guard<std::mutex> held(g_texture_lock);
    all.assign(g_textures.begin(), g_textures.end());
  }
  std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) {
    return a.second.draws > b.second.draws;
  });
  fprintf(stderr, "[gl] draws per texture, busiest first:\n");
  for (size_t i = 0; i < all.size() && i < 10; ++i)
    fprintf(stderr, "[gl]   texture %-4u %5dx%-5d %ld draws\n", all[i].first,
            all[i].second.width, all[i].second.height, all[i].second.draws);
  // The busiest few, not just the busiest: an atlas the whole scene shares
  // will always top the list, and the one that answers the question is
  // usually the small texture just below it with an implausible count.
  for (size_t i = 0; i < all.size() && i < 4; ++i)
    if (all[i].first)
      DumpTexture(all[i].first, all[i].second.width, all[i].second.height);
}

// An address in the low pages is an offset that was meant to be relative to a
// buffer, not a pointer to read.
bool LooksLikeAnOffset(const void* p) {
  const uintptr_t v = reinterpret_cast<uintptr_t>(p);
  return v != 0 && v < 0x10000;
}

bool NoBufferFor(GLenum which, GLint* bound) {
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  if (!get_int) return false;
  *bound = 0;
  get_int(which, bound);
  return *bound == 0;
}

void SkipNote(const char* why, unsigned long long at) {
  static long skipped = 0;
  ++skipped;
  if (skipped <= 3 || skipped % 1000 == 0)
    fprintf(stderr, "[gl] skipped a draw: %s (%#llx) (%ld so far)\n", why,
            at, skipped);
}

bool IndicesAreUnusable(const void* indices) {
  GLint bound = 0;
  if (LooksLikeAnOffset(indices) &&
      NoBufferFor(0x8895 /* GL_ELEMENT_ARRAY_BUFFER_BINDING */, &bound)) {
    SkipNote("index offset with no element array buffer bound",
             reinterpret_cast<uintptr_t>(indices));
    return true;
  }
  // And the same question about every attribute the draw will read. An
  // attribute whose pointer is an offset and whose buffer binding is zero is
  // a client pointer into the first page of memory, and the driver dereferences
  // it without checking -- which is a fault inside the driver, blamed on the
  // driver, with nothing to say the state was set up wrong two calls earlier.
  auto get_attr = reinterpret_cast<void (*)(GLuint, GLenum, GLint*)>(
      Real("glGetVertexAttribiv"));
  auto get_attr_ptr = reinterpret_cast<void (*)(GLuint, GLenum, void**)>(
      Real("glGetVertexAttribPointerv"));
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  if (!get_attr || !get_attr_ptr || !get_int) return false;
  GLint most = 0;
  get_int(0x8869 /* GL_MAX_VERTEX_ATTRIBS */, &most);
  if (most <= 0 || most > 64) most = 16;
  for (GLint i = 0; i < most; ++i) {
    GLint on = 0;
    get_attr(static_cast<GLuint>(i), 0x8622 /* ARRAY_ENABLED */, &on);
    if (!on) continue;
    GLint from = 0;
    get_attr(static_cast<GLuint>(i), 0x889F /* ARRAY_BUFFER_BINDING */, &from);
    if (from) continue;
    void* at = nullptr;
    get_attr_ptr(static_cast<GLuint>(i), 0x8645 /* ARRAY_POINTER */, &at);
    if (!LooksLikeAnOffset(at)) continue;
    SkipNote("an enabled attribute is an offset with no array buffer bound",
             reinterpret_cast<uintptr_t>(at));
    return true;
  }
  return false;
}

void DrawElements(GLenum mode, GLsizei count, GLenum type, const void* indices) {
  if (IndicesAreUnusable(indices)) return;
  const unsigned bound = BoundTexture();
  if (TextureIsSkipped(bound)) return;
  TraceThisDraw(bound, static_cast<int>(count));
  WhoDrew(bound);
  ShowVertices(bound, count, type, indices);
  NoteDraw();
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
  if (level == 0) NoteTexture(static_cast<int>(w), static_cast<int>(h));
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
// Who fills a vertex buffer.
//
// This layer's draws all start at index 0 in one of two buffers, so the
// geometry is built once and replayed every frame -- which means the draw
// call is the wrong place to look for the mistake. The moment the buffer is
// filled is the right one, and the frame ring names the guest code that did
// it. ARC_GL_BUILDER=<buffer> reports the first fill of that buffer.
void NoteBufferFill(const char* how, intptr_t size) {
  static const char* const want = getenv("ARC_GL_BUILDER");
  if (!want) return;
  auto get_int = reinterpret_cast<void (*)(GLenum, GLint*)>(
      Real("glGetIntegerv"));
  if (!get_int) return;
  GLint bound = 0;
  get_int(0x8894 /* GL_ARRAY_BUFFER_BINDING */, &bound);
  if (bound != atoi(want)) return;
  static int left = 2;
  if (left <= 0) return;
  --left;
  fprintf(stderr, "[gl] %s filled buffer %d with %lld bytes, from:\n",
          how, bound, static_cast<long long>(size));
  const size_t n = arc_frame_count();
  for (size_t i = 0; i < n && i < 28; ++i)
    fprintf(stderr, "[gl]   %#llx\n",
            static_cast<unsigned long long>(arc_frame_at(i)));
}

void BufferData(GLenum target, intptr_t size, const void* data, GLenum use) {
  auto real = reinterpret_cast<void (*)(GLenum, intptr_t, const void*,
                                        GLenum)>(Real("glBufferData"));
  if (real) real(target, size, data, use);
  if (target == 0x8892) NoteBufferFill("glBufferData", size);
}

void BufferSubData(GLenum target, intptr_t at, intptr_t size,
                   const void* data) {
  auto real = reinterpret_cast<void (*)(GLenum, intptr_t, intptr_t,
                                        const void*)>(Real("glBufferSubData"));
  if (real) real(target, at, size, data);
  if (target == 0x8892) NoteBufferFill("glBufferSubData", size);
}

// The other half of a sprite's colour. The shader multiplies the texture by
// the vertex colour and then by this uniform, so a layer that should be a
// faint wash and a layer that should be solid differ here and nowhere else.
float g_last_uniform4[4] = {1, 1, 1, 1};

void Uniform4fv(GLint location, GLsizei count, const float* v) {
  auto real = reinterpret_cast<void (*)(GLint, GLsizei, const float*)>(
      Real("glUniform4fv"));
  if (real) real(location, count, v);
  if (v && count >= 1) memcpy(g_last_uniform4, v, sizeof g_last_uniform4);
}

void UniformMatrix4fv(GLint location, GLsizei count, unsigned char transpose,
                      const float* v) {
  auto real = reinterpret_cast<void (*)(GLint, GLsizei, unsigned char,
                                        const float*)>(
      Real("glUniformMatrix4fv"));
  if (real) real(location, count, transpose, v);
  // Kept so a draw can say which transform was in force when it was issued.
  // Two layers that disagree about where the world is will have set different
  // matrices, and that is visible here and nowhere else.
  if (v) memcpy(g_last_matrix, v, sizeof g_last_matrix);
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
  ++g_frame;
  // The function census covers one frame, so it is reported and reset here --
  // at the top of the next one. Reported for the frame named by
  // ARC_GL_TRACE_FRAME, so it lines up with that frame's draw log.
  // Reported twice: once at the start of the traced frame, which only
  // clears the tally accumulated since the program began, and again at the
  // start of the next -- and that second report is one frame's worth.
  // Whichever comes first: the frame the trace names, or the frame after the
  // census marker fired. The second is how one-time work gets its own report.
  if (arc_census_pending() ||
      (TraceFrame() &&
       (g_frame == TraceFrame() || g_frame == TraceFrame() + 1)))
    arc_census_report(getenv("ARC_FN_CENSUS_TOP")
                          ? atoi(getenv("ARC_FN_CENSUS_TOP"))
                          : 24);
  if (CensusAfter()) {
    static int frames = 0;
    static bool reported = false;
    if (++frames >= CensusAfter() && !reported) {
      reported = true;
      ReportCensus();
    }
  }
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
  // Every name resolved this way, because the import table does not list
  // them. A float-taking entry point that arrives here reaches the driver
  // through the twelve-integer thunk, which cannot carry a float -- the same
  // fault the four above exist to avoid, on names nobody knew to look for.
  {
    static const bool trace = getenv("ARC_TRACE_GLPROC") != nullptr;
    if (trace) fprintf(stderr, "[glproc] %s\n", name);
  }
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
  if (strcmp(name, "glUniform4fv") == 0)
    return reinterpret_cast<uint64_t>(&Uniform4fv);
  if (strcmp(name, "glBufferData") == 0)
    return reinterpret_cast<uint64_t>(&BufferData);
  if (strcmp(name, "glBufferSubData") == 0)
    return reinterpret_cast<uint64_t>(&BufferSubData);
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
