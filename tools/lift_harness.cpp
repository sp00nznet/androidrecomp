// Test surface for whole-function verification.
//
// The lifted program is a library of C functions over an Arm64Ctx, but it can
// only run against the image's real data: constants, vtables and relocated
// pointers all live there. So the harness loads the image exactly as the host
// does, and hands the driver the base address it landed at -- which lets the
// oracle map its own copy at the same numeric address and see the same memory.

#include <memory>
#include <string>
#include <vector>

#include "arm64_context.h"
#include "elf_image.h"
#include "lifted.h"
#include "shim.h"

namespace {
arc::ElfImage g_image;
std::vector<std::unique_ptr<arc::ElfImage>> g_deps;

void AnnounceImage(const std::string& name, uint64_t base, uint64_t span) {
  for (size_t i = 0; i < ARC_IMAGE_COUNT; ++i) {
    const char* known = arc_image_name(i);
    if (known && name == known) {
      arc_set_image(i, base, span);
      return;
    }
  }
}
}  // namespace

// Nothing leaves a Windows DLL unless it says so.
#if defined(_WIN32)
#define ARC_EXPORT __declspec(dllexport)
#else
#define ARC_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

// Returns the host address the image was mapped at, or 0 on failure.
ARC_EXPORT uint64_t arc_test_load(const char* path) {
  std::string err;
  const std::string p(path);
  const size_t cut = p.find_last_of("/\\");
  const std::string dir = cut == std::string::npos ? "." : p.substr(0, cut);

  auto resolve = [](const char* name) -> uint64_t {
    for (const auto& d : g_deps)
      if (uint64_t a = d->Lookup(name)) return a;
    return arc::ShimResolve(name);
  };

  for (const std::string& need : arc::ElfImage::ReadNeeded(p)) {
    auto img = std::make_unique<arc::ElfImage>();
    if (img->Load(dir + "/" + need, resolve, &err)) {
      arc::ShimRegisterImage(img.get());
      AnnounceImage(need, reinterpret_cast<uint64_t>(img->base()), img->span());
      g_deps.push_back(std::move(img));
    }
  }
  if (!g_image.Load(p, resolve, &err)) return 0;
  arc::ShimRegisterImage(&g_image);
  const std::string base_name =
      cut == std::string::npos ? p : p.substr(cut + 1);
  AnnounceImage(base_name, reinterpret_cast<uint64_t>(g_image.base()),
                g_image.span());
  return reinterpret_cast<uint64_t>(g_image.base());
}

ARC_EXPORT uint64_t arc_test_span() { return g_image.span(); }

// Calls the lifted function at an image offset, through the same dispatch
// table an indirect branch would use.
ARC_EXPORT void arc_test_call(Arm64Ctx* c, uint64_t offset) {
  arc_dispatch(c, c->image_base + offset);
}

ARC_EXPORT size_t arc_test_ctx_size() { return sizeof(Arm64Ctx); }

}  // extern "C"
