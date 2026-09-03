// Loads an aarch64 ELF shared object into host memory and relocates it.
//
// This is the piece both execution paths need. On an arm64 host the mapped
// image is directly callable, which is how the engine runs before a lifter
// exists. On any other host it cannot execute, but the same load -- segment
// layout, relocation, symbol resolution -- is what the lifter consumes, so it
// is developed and verified everywhere.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace arc {

struct Segment {
  uint64_t vaddr = 0;
  uint64_t memsz = 0;
  uint32_t flags = 0;  // PF_X=1, PF_W=2, PF_R=4
};

struct Import {
  std::string name;
  std::string version;   // from .gnu.version_r, e.g. "LIBC"; empty if unversioned
  uint64_t bound_to = 0; // host address it was bound to (a trap slot if unresolved)
  bool resolved = false;
};

// Maps an imported symbol name to a host address, or 0 if the shim has no
// implementation yet.
using Resolver = std::function<uint64_t(const char* name)>;

class ElfImage {
 public:
  ~ElfImage();

  bool Load(const std::string& path, const Resolver& resolve, std::string* err);

  // The DT_NEEDED list, read from a file without mapping it. Lets a caller
  // load an image's APK-shipped dependencies before the image itself, so they
  // can satisfy its imports.
  static std::vector<std::string> ReadNeeded(const std::string& path);

  // Host address of an exported symbol, or 0.
  uint64_t Lookup(const char* name) const;

  // Every defined symbol whose name starts with `prefix`, sorted. Passing
  // "Java_" enumerates a library's JNI entry points, which is how a title's
  // host contract is discovered in the first place.
  std::vector<std::string> ExportsWithPrefix(const char* prefix) const;

  // Apply the segment page protections recorded in the program headers. Only
  // meaningful when the image will actually execute (arm64 host); harmless
  // otherwise. Kept separate from Load() so relocation runs against writable
  // memory.
  bool Protect(std::string* err);

  uint8_t* base() const { return base_; }
  uint64_t span() const { return span_; }
  const std::vector<Segment>& segments() const { return segments_; }
  const std::vector<std::string>& needed() const { return needed_; }
  const std::vector<Import>& imports() const { return imports_; }
  size_t symbol_count() const { return symcount_; }
  size_t relocations_applied() const { return relocs_; }
  const std::vector<uint64_t>& init_array() const { return init_array_; }

  // The program headers, inside the mapped image. dl_iterate_phdr hands these
  // to the C++ unwinder, which is how it finds each image's .eh_frame -- so
  // exceptions in the guest depend on them.
  const void* phdrs() const { return phdrs_; }
  size_t phnum() const { return phnum_; }

 private:
  uint64_t SymbolValue(uint32_t index, const Resolver& resolve);
  const char* SymbolName(uint32_t index) const;

  uint8_t* base_ = nullptr;
  uint64_t span_ = 0;
  uint8_t* traps_ = nullptr;  // guard page; unresolved imports point in here

  const uint8_t* symtab_ = nullptr;
  const char* strtab_ = nullptr;
  const uint16_t* versym_ = nullptr;
  size_t symcount_ = 0;
  size_t relocs_ = 0;

  std::vector<Segment> segments_;
  std::vector<std::string> needed_;
  std::vector<Import> imports_;
  std::vector<uint64_t> init_array_;
  std::vector<std::string> verneed_;  // version index -> name
  const void* phdrs_ = nullptr;
  size_t phnum_ = 0;
};

}  // namespace arc
