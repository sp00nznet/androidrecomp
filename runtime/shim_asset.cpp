// The Android asset manager, over an ordinary directory.
//
// An APK carries the game's own files under `assets/`, and the engine reads
// every one of them through this interface rather than through open() -- so
// without it a title loads nothing at all. Family Guy says so in its own log
// before giving up: "FileUtilsAndroid::assetmanager is nullptr", then an
// assertion, then an uncaught exception.
//
// There is nothing to emulate here. The APK is a zip and the host has a
// filesystem, so the honest implementation is a directory: point this at an
// extracted `assets/` and the paths the engine asks for are the paths on disk.
// Nothing is decompressed, cached or rewritten.
//
// The one piece of state that surprises: `AAssetDir_getNextFileName` returns a
// pointer the caller may hold until it asks again, so the directory keeps the
// name it last handed out. Returning a temporary's data would be a use-after
// -free the moment the caller does anything between iterations.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "shim.h"

namespace arc {
namespace {

std::string g_root;

// Opaque to the guest: it only ever holds the pointer and hands it back.
struct Manager {
  int tag;
};
Manager g_manager{0xA55E7};

struct Asset {
  FILE* file = nullptr;
  int64_t length = 0;
};

struct AssetDir {
  std::vector<std::string> names;
  size_t next = 0;
  std::string current;  // outlives the call, see the note above
};

// Asset paths are relative to the assets root and always use '/'. A leading
// slash or a "assets/" prefix both show up in practice; neither is part of the
// name on disk.
std::filesystem::path Resolve(const char* name) {
  if (g_root.empty() || !name) return {};
  const char* p = name;
  while (*p == '/') ++p;
  if (strncmp(p, "assets/", 7) == 0) p += 7;
  return std::filesystem::path(g_root) / p;
}

void* ManagerFromJava(void*, void*) { return &g_manager; }

// The third argument is the access mode -- streaming, random, buffered. It is
// advice about how the file will be read, not about what it contains, so the
// same file answers all of them.
void* ManagerOpen(void*, const char* name, int) {
  const std::filesystem::path path = Resolve(name);
  if (path.empty()) return nullptr;
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec)) return nullptr;
  FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.string().c_str(), "rb") != 0) file = nullptr;
#else
  file = fopen(path.string().c_str(), "rb");
#endif
  if (!file) return nullptr;
  auto* asset = new Asset();
  asset->file = file;
  asset->length = static_cast<int64_t>(std::filesystem::file_size(path, ec));
  return asset;
}

int64_t AssetRead(void* handle, void* buffer, uint64_t count) {
  auto* asset = static_cast<Asset*>(handle);
  if (!asset || !asset->file) return -1;
  return static_cast<int64_t>(fread(buffer, 1, static_cast<size_t>(count),
                                    asset->file));
}

int64_t AssetGetLength(void* handle) {
  auto* asset = static_cast<Asset*>(handle);
  return asset ? asset->length : 0;
}

int64_t AssetSeek(void* handle, int64_t offset, int whence) {
  auto* asset = static_cast<Asset*>(handle);
  if (!asset || !asset->file) return -1;
  if (fseek(asset->file, static_cast<long>(offset), whence) != 0) return -1;
  return ftell(asset->file);
}

int64_t AssetGetRemainingLength(void* handle) {
  auto* asset = static_cast<Asset*>(handle);
  if (!asset || !asset->file) return 0;
  return asset->length - ftell(asset->file);
}

void AssetClose(void* handle) {
  auto* asset = static_cast<Asset*>(handle);
  if (!asset) return;
  if (asset->file) fclose(asset->file);
  delete asset;
}

// Answers "not available", which is a real answer rather than a failure: on
// Android a compressed asset has no descriptor to hand out either, so every
// caller already has a path that reads the file instead.
int AssetOpenFileDescriptor(void*, int64_t*, int64_t*) { return -1; }

void* ManagerOpenDir(void*, const char* name) {
  const std::filesystem::path path = Resolve(name && *name ? name : ".");
  if (path.empty()) return nullptr;
  std::error_code ec;
  auto* dir = new AssetDir();
  // A missing directory is an empty one, not an error: the caller iterates and
  // gets nothing, which is what Android does for an assets subdirectory that
  // was never packaged.
  for (const auto& entry : std::filesystem::directory_iterator(path, ec))
    if (entry.is_regular_file(ec))
      dir->names.push_back(entry.path().filename().string());
  return dir;
}

const char* AssetDirGetNextFileName(void* handle) {
  auto* dir = static_cast<AssetDir*>(handle);
  if (!dir || dir->next >= dir->names.size()) return nullptr;
  dir->current = dir->names[dir->next++];
  return dir->current.c_str();
}

void AssetDirRewind(void* handle) {
  if (auto* dir = static_cast<AssetDir*>(handle)) dir->next = 0;
}

void AssetDirClose(void* handle) { delete static_cast<AssetDir*>(handle); }

struct Entry {
  const char* name;
  void* fn;
};

const Entry kEntries[] = {
    {"AAssetManager_fromJava", reinterpret_cast<void*>(&ManagerFromJava)},
    {"AAssetManager_open", reinterpret_cast<void*>(&ManagerOpen)},
    {"AAssetManager_openDir", reinterpret_cast<void*>(&ManagerOpenDir)},
    {"AAsset_read", reinterpret_cast<void*>(&AssetRead)},
    {"AAsset_seek", reinterpret_cast<void*>(&AssetSeek)},
    {"AAsset_seek64", reinterpret_cast<void*>(&AssetSeek)},
    {"AAsset_getLength", reinterpret_cast<void*>(&AssetGetLength)},
    {"AAsset_getLength64", reinterpret_cast<void*>(&AssetGetLength)},
    {"AAsset_getRemainingLength",
     reinterpret_cast<void*>(&AssetGetRemainingLength)},
    {"AAsset_getRemainingLength64",
     reinterpret_cast<void*>(&AssetGetRemainingLength)},
    {"AAsset_close", reinterpret_cast<void*>(&AssetClose)},
    {"AAsset_openFileDescriptor",
     reinterpret_cast<void*>(&AssetOpenFileDescriptor)},
    {"AAsset_openFileDescriptor64",
     reinterpret_cast<void*>(&AssetOpenFileDescriptor)},
    {"AAssetDir_getNextFileName",
     reinterpret_cast<void*>(&AssetDirGetNextFileName)},
    {"AAssetDir_rewind", reinterpret_cast<void*>(&AssetDirRewind)},
    {"AAssetDir_close", reinterpret_cast<void*>(&AssetDirClose)},
};

}  // namespace

void ShimSetAssetRoot(const char* path) { g_root = path ? path : ""; }

const char* ShimAssetRoot() { return g_root.c_str(); }

uint64_t ShimResolveAsset(const char* name) {
  // Only claimed once a root is set. Left unresolved otherwise, the name shows
  // up on the outstanding-import list, which says what is missing far more
  // clearly than an asset manager that opens nothing.
  if (g_root.empty()) return 0;
  for (const Entry& e : kEntries)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimAssetCount() { return sizeof(kEntries) / sizeof(kEntries[0]); }

}  // namespace arc
