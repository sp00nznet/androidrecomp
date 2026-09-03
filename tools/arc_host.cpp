// arc_host -- load an Android game's native engine and report what it still needs.
//
// Point it at any arm64 Android `.so`. It maps the image, applies its
// relocations, binds its imports through the shim, and prints what nothing yet
// provides, grouped by the library that owes it. That list is the port's work
// queue, and it shrinks as the shim grows.
//
// On an arm64 host the loaded image is callable, and this is where a real host
// process starts. Everywhere else it is load-and-verify: the segment layout,
// relocations and symbol binding are exactly what a lifter consumes, so they
// are exercised on whatever machine you have.
//
// A title's *host contract* -- the JNI entry points its Java side used to call
// -- differs per game, so it is passed in rather than compiled in. With no
// --contract, every `Java_*` export is listed, which is how you discover the
// contract for a new title in the first place.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#if defined(ARC_HAVE_SDL2)
#include <SDL.h>
#endif

#include "elf_image.h"
#include "shim.h"
#include "window.h"

namespace {

// Bionic only version-tags libc/libm/libdl, so most imports arrive unversioned
// in one heap. Name prefixes say which shim owes them, which is the question
// the work list actually needs answered.
std::string Provider(const arc::Import& i) {
  if (!i.version.empty()) return i.version;
  const std::string& n = i.name;
  auto starts = [&n](const char* p) { return n.rfind(p, 0) == 0; };
  if (starts("_Z") || starts("__cxa") || starts("__gxx")) return "libc++_shared.so";
  if (starts("gl")) return "libGLESv2.so / libGLESv1_CM.so";
  if (starts("egl")) return "libEGL.so";
  if (starts("SL") || starts("sl")) return "libOpenSLES.so";
  if (starts("alc") || starts("al")) return "libopenal.so";
  if (starts("AAsset") || starts("ANative") || starts("AConfiguration") ||
      starts("AInput") || starts("ALooper"))
    return "libandroid.so";
  if (starts("AndroidBitmap")) return "libjnigraphics.so";
  if (starts("__android_log")) return "liblog.so";
  if (starts("inflate") || starts("deflate") || starts("crc32") ||
      starts("compress") || starts("uncompress") || starts("gz") ||
      starts("zlib") || starts("adler32"))
    return "libz.so";
  return "(unclassified)";
}

std::vector<std::string> ReadContract(const std::string& path) {
  std::vector<std::string> names;
  std::ifstream f(path);
  std::string line;
  while (std::getline(f, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
      line.pop_back();
    if (!line.empty() && line[0] != '#') names.push_back(line);
  }
  return names;
}

// Drives the frame until the user quits. Once a title's JNI bridge exists, the
// clear here is replaced by the engine's own render call and the resize
// forwarded to its resize hook.
void RunLoop(arc::Window& window, long frame_limit) {
#if defined(ARC_HAVE_SDL2)
  auto clear_color = reinterpret_cast<void (*)(float, float, float, float)>(
      SDL_GL_GetProcAddress("glClearColor"));
  auto clear =
      reinterpret_cast<void (*)(unsigned)>(SDL_GL_GetProcAddress("glClear"));
  const unsigned kColorAndDepth = 0x4000 | 0x0100;

  for (long frame = 0; window.PumpEvents(); ++frame) {
    if (frame_limit > 0 && frame >= frame_limit) break;
    if (window.TakeResized())
      printf("resize     %dx%d\n", window.width(), window.height());
    if (clear_color && clear) {
      clear_color(0.05f, 0.07f, 0.11f, 1.0f);
      clear(kColorAndDepth);
    }
    window.Present();
  }
#else
  (void)window;
  (void)frame_limit;
#endif
}

}  // namespace

int main(int argc, char** argv) {
  const char* lib = nullptr;
  std::string contract_path;
  bool want_window = false;
  long frame_limit = 0;  // 0 = run until the user quits

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--window") == 0)
      want_window = true;
    else if (strncmp(argv[i], "--frames=", 9) == 0)
      frame_limit = strtol(argv[i] + 9, nullptr, 10);
    else if (strncmp(argv[i], "--contract=", 11) == 0)
      contract_path = argv[i] + 11;
    else
      lib = argv[i];
  }
  if (!lib) {
    fprintf(stderr,
            "usage: %s [--window] [--frames=N] [--contract=FILE] <library.so>\n",
            argv[0]);
    return 2;
  }

  // The window comes first on purpose. GL imports bind by asking the GL driver
  // for each name, and that needs a current context -- the same order Android
  // uses, where Java has a surface before it calls the engine.
  arc::Window window;
  std::string window_err;
  if (want_window) {
    if (!window.Open("androidrecomp", 1280, 720, &window_err)) {
      fprintf(stderr, "window failed: %s\n", window_err.c_str());
      return 1;
    }
    printf("window     %dx%d, %s\n\n", window.width(), window.height(),
           window.Describe().c_str());
  }

  const std::filesystem::path path(lib);
  const std::filesystem::path dir = path.parent_path();
  std::string err;

  // Libraries the APK ships alongside the engine are loaded and used to satisfy
  // its imports. Everything else in DT_NEEDED is an Android system library and
  // falls to the shim. This is what answers libc++_shared's NDK-mangled
  // symbols, which no host STL can provide.
  std::vector<std::unique_ptr<arc::ElfImage>> deps;
  auto resolve = [&deps](const char* name) -> uint64_t {
    for (const auto& d : deps)
      if (uint64_t a = d->Lookup(name)) return a;
    return arc::ShimResolve(name);
  };

  printf("dependencies\n");
  for (const std::string& name : arc::ElfImage::ReadNeeded(path.string())) {
    const std::filesystem::path p = dir / name;
    if (!std::filesystem::exists(p)) {
      printf("  %-22s system -- shimmed\n", name.c_str());
      continue;
    }
    auto img = std::make_unique<arc::ElfImage>();
    if (!img->Load(p.string(), resolve, &err)) {
      printf("  %-22s FAILED: %s\n", name.c_str(), err.c_str());
      continue;
    }
    printf("  %-22s loaded -- %zu symbols, %zu relocs\n", name.c_str(),
           img->symbol_count(), img->relocations_applied());
    arc::ShimRegisterImage(img.get());
    deps.push_back(std::move(img));
  }

  arc::ElfImage image;
  if (!image.Load(path.string(), resolve, &err)) {
    fprintf(stderr, "load failed: %s\n", err.c_str());
    return 1;
  }

  // dlsym and the C++ unwinder's dl_iterate_phdr both search registered
  // images, so every image the host maps has to be announced.
  arc::ShimRegisterImage(&image);

  printf("\nimage      %s\n", path.filename().string().c_str());
  printf("base       %p, span %.1f MB\n", static_cast<void*>(image.base()),
         image.span() / 1e6);
  printf("segments   %zu\n", image.segments().size());
  for (const arc::Segment& s : image.segments()) {
    printf("           %#010llx +%#010llx  %c%c%c\n",
           static_cast<unsigned long long>(s.vaddr),
           static_cast<unsigned long long>(s.memsz),
           (s.flags & 4) ? 'r' : '-', (s.flags & 2) ? 'w' : '-',
           (s.flags & 1) ? 'x' : '-');
  }
  printf("symbols    %zu\n", image.symbol_count());
  printf("relocs     %zu applied\n", image.relocations_applied());
  printf("initarray  %zu constructors\n", image.init_array().size());

  // The work list, across every image loaded: what nothing yet provides,
  // grouped by the library that owes it.
  std::map<std::string, std::vector<std::string>> outstanding;
  size_t total = 0, resolved = 0;
  auto tally = [&](const arc::ElfImage& img) {
    for (const arc::Import& i : img.imports()) {
      ++total;
      if (i.resolved) {
        ++resolved;
        continue;
      }
      auto& bucket = outstanding[Provider(i)];
      if (std::find(bucket.begin(), bucket.end(), i.name) == bucket.end())
        bucket.push_back(i.name);
    }
  };
  for (const auto& d : deps) tally(*d);
  tally(image);

  size_t unique_outstanding = 0;
  for (const auto& kv : outstanding) unique_outstanding += kv.second.size();
  printf("\nimports    %zu total, %zu resolved, %zu outstanding (%zu unique)\n",
         total, resolved, total - resolved, unique_outstanding);
  for (const auto& kv : outstanding) {
    printf("\n  %s -- %zu\n", kv.first.c_str(), kv.second.size());
    for (const std::string& n : kv.second) printf("    %s\n", n.c_str());
  }

  int missing = 0;
  if (contract_path.empty()) {
    // No contract given: show what the library offers, which is how a new
    // title's contract gets discovered.
    std::vector<std::string> jni = image.ExportsWithPrefix("Java_");
    printf("\nJNI exports (%zu) -- pass the ones your host drives via --contract\n",
           jni.size());
    for (const std::string& n : jni) printf("  %s\n", n.c_str());
  } else {
    const std::vector<std::string> contract = ReadContract(contract_path);
    printf("\nhost contract (%s)\n", contract_path.c_str());
    for (const std::string& name : contract) {
      uint64_t addr = image.Lookup(name.c_str());
      if (!addr) ++missing;
      size_t cut = name.rfind('_');
      printf("  %-28s %s\n",
             cut == std::string::npos ? name.c_str() : name.c_str() + cut + 1,
             addr ? "found" : "MISSING");
    }
    if (missing) {
      fprintf(stderr, "\n%d contract entry point(s) missing -- wrong library?\n",
              missing);
      return 1;
    }
  }

  if (!image.Protect(&err)) {
    fprintf(stderr, "protect failed: %s\n", err.c_str());
    return 1;
  }

#if defined(__aarch64__) || defined(_M_ARM64)
  printf("\narm64 host: image is executable once the work list is empty.\n");
#else
  printf("\nx86-64 host: image loaded and relocated but not executable here;\n"
         "             running it needs a lifter.\n");
#endif

  if (want_window) {
    // Calling the engine's render path needs a JNIEnv to hand it, which is a
    // per-title bridge. Until then the host owns the frame: this proves the
    // window, the context and the swap chain are live, and that the loop the
    // engine will eventually be driven from actually runs.
    printf("\nwindow open -- escape or close to quit\n");
    RunLoop(window, frame_limit);
    window.Close();
  }
  return 0;
}
