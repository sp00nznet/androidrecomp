#include "elf_image.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace arc {
namespace {

// Minimal ELF64 little-endian definitions. Pulling in a full ELF library for
// four relocation types and one program header walk is not worth a dependency.
#pragma pack(push, 1)
struct Ehdr {
  uint8_t ident[16];
  uint16_t type, machine;
  uint32_t version;
  uint64_t entry, phoff, shoff;
  uint32_t flags;
  uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Phdr {
  uint32_t type, flags;
  uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
struct Dyn {
  int64_t tag;
  uint64_t val;
};
struct Sym {
  uint32_t name;
  uint8_t info, other;
  uint16_t shndx;
  uint64_t value, size;
};
constexpr uint8_t kSttFunc = 2;  // the low nibble of Sym::info
struct Rela {
  uint64_t offset, info;
  int64_t addend;
};
struct Verneed {
  uint16_t version, cnt;
  uint32_t file, aux, next;
};
struct Vernaux {
  uint32_t hash;
  uint16_t flags, other;
  uint32_t name, next;
};
#pragma pack(pop)

constexpr uint32_t PT_LOAD = 1, PT_DYNAMIC = 2;
constexpr uint32_t PF_X = 1, PF_W = 2;

constexpr int64_t DT_NEEDED = 1, DT_PLTRELSZ = 2, DT_HASH = 4, DT_STRTAB = 5,
                  DT_SYMTAB = 6, DT_RELA = 7, DT_RELASZ = 8, DT_JMPREL = 23,
                  DT_INIT_ARRAY = 25, DT_INIT_ARRAYSZ = 27,
                  DT_VERSYM = 0x6ffffff0, DT_VERNEED = 0x6ffffffe,
                  DT_VERNEEDNUM = 0x6fffffff;

// The only four relocation types this image uses. Anything else is a surprise
// and is reported rather than silently skipped.
constexpr uint32_t R_AARCH64_ABS64 = 257, R_AARCH64_GLOB_DAT = 1025,
                   R_AARCH64_JUMP_SLOT = 1026, R_AARCH64_RELATIVE = 1027;

constexpr uint16_t SHN_UNDEF = 0;
constexpr uint64_t kPageSize = 4096;

uint64_t RoundUp(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

void* MapRW(size_t bytes) {
#if defined(_WIN32)
  return VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
  void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
#endif
}

void* MapGuard(size_t bytes) {
#if defined(_WIN32)
  return VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
#else
  void* p = mmap(nullptr, bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
#endif
}

void Unmap(void* p, size_t bytes) {
  if (!p) return;
#if defined(_WIN32)
  (void)bytes;
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munmap(p, bytes);
#endif
}

bool SetProtection(void* addr, size_t bytes, uint32_t flags) {
#if defined(_WIN32)
  DWORD want = PAGE_READONLY;
  if (flags & PF_X)
    want = (flags & PF_W) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
  else if (flags & PF_W)
    want = PAGE_READWRITE;
  DWORD old = 0;
  return VirtualProtect(addr, bytes, want, &old) != 0;
#else
  int want = PROT_READ;
  if (flags & PF_X) want |= PROT_EXEC;
  if (flags & PF_W) want |= PROT_WRITE;
  return mprotect(addr, bytes, want) == 0;
#endif
}

}  // namespace

ElfImage::~ElfImage() {
  Unmap(base_, span_);
  Unmap(traps_, kPageSize);
}

const char* ElfImage::SymbolName(uint32_t index) const {
  const Sym* s = reinterpret_cast<const Sym*>(symtab_ + index * sizeof(Sym));
  return strtab_ + s->name;
}

uint64_t ElfImage::SymbolValue(uint32_t index, const Resolver& resolve) {
  const Sym* s = reinterpret_cast<const Sym*>(symtab_ + index * sizeof(Sym));
  if (s->shndx != SHN_UNDEF) return reinterpret_cast<uint64_t>(base_) + s->value;

  const char* name = strtab_ + s->name;
  for (const Import& i : imports_)  // ponytail: linear over ~481, no map needed
    if (i.name == name) return i.bound_to;

  Import imp;
  imp.name = name;
  if (versym_) {
    uint16_t v = versym_[index] & 0x7fff;
    if (v < verneed_.size()) imp.version = verneed_[v];
  }
  uint64_t addr = resolve ? resolve(name) : 0;
  imp.resolved = addr != 0;
  // Unresolved imports bind into a guard page, one slot each, so touching one
  // faults at an address that identifies which symbol was missing -- rather
  // than a null dereference that tells you nothing.
  imp.bound_to = imp.resolved
                     ? addr
                     : reinterpret_cast<uint64_t>(traps_) + imports_.size() * 8;
  imports_.push_back(imp);
  return imp.bound_to;
}

std::vector<std::string> ElfImage::ReadNeeded(const std::string& path) {
  std::vector<std::string> out;
  std::ifstream f(path, std::ios::binary);
  if (!f) return out;
  std::vector<uint8_t> file((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
  if (file.size() < sizeof(Ehdr)) return out;

  const Ehdr* eh = reinterpret_cast<const Ehdr*>(file.data());
  static const uint8_t kMagic[4] = {0x7f, 'E', 'L', 'F'};
  if (memcmp(eh->ident, kMagic, 4) != 0 || eh->machine != 183) return out;

  const Phdr* ph = reinterpret_cast<const Phdr*>(file.data() + eh->phoff);
  // Nothing is mapped here, so dynamic-section addresses have to be walked
  // back to file offsets through the PT_LOAD entries that contain them.
  auto to_offset = [&](uint64_t vaddr) -> const uint8_t* {
    for (uint16_t i = 0; i < eh->phnum; ++i) {
      if (ph[i].type != PT_LOAD) continue;
      if (vaddr >= ph[i].vaddr && vaddr < ph[i].vaddr + ph[i].filesz)
        return file.data() + ph[i].offset + (vaddr - ph[i].vaddr);
    }
    return nullptr;
  };

  for (uint16_t i = 0; i < eh->phnum; ++i) {
    if (ph[i].type != PT_DYNAMIC) continue;
    const Dyn* dyn = reinterpret_cast<const Dyn*>(to_offset(ph[i].vaddr));
    if (!dyn) return out;
    const char* strtab = nullptr;
    std::vector<uint32_t> offsets;
    for (const Dyn* d = dyn; d->tag != 0; ++d) {
      if (d->tag == DT_STRTAB)
        strtab = reinterpret_cast<const char*>(to_offset(d->val));
      else if (d->tag == DT_NEEDED)
        offsets.push_back(static_cast<uint32_t>(d->val));
    }
    if (strtab)
      for (uint32_t off : offsets) out.push_back(strtab + off);
    break;
  }
  return out;
}

bool ElfImage::Load(const std::string& path, const Resolver& resolve,
                    std::string* err) {
  auto fail = [&](const char* m) {
    if (err) *err = m;
    return false;
  };

  std::ifstream f(path, std::ios::binary);
  if (!f) return fail("cannot open file");
  std::vector<uint8_t> file((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
  if (file.size() < sizeof(Ehdr)) return fail("truncated");

  const Ehdr* eh = reinterpret_cast<const Ehdr*>(file.data());
  static const uint8_t kMagic[4] = {0x7f, 'E', 'L', 'F'};
  if (memcmp(eh->ident, kMagic, 4) != 0) return fail("not an ELF");
  if (eh->ident[4] != 2 || eh->ident[5] != 1) return fail("not ELF64 LE");
  if (eh->machine != 183) return fail("not aarch64 (EM_AARCH64 is 183)");

  const Phdr* ph = reinterpret_cast<const Phdr*>(file.data() + eh->phoff);
  const Phdr* dynamic = nullptr;
  for (uint16_t i = 0; i < eh->phnum; ++i) {
    if (ph[i].type == PT_LOAD) {
      span_ = std::max(span_, RoundUp(ph[i].vaddr + ph[i].memsz, kPageSize));
      segments_.push_back({ph[i].vaddr, ph[i].memsz, ph[i].flags});
    } else if (ph[i].type == PT_DYNAMIC) {
      dynamic = &ph[i];
    }
  }
  if (!span_) return fail("no PT_LOAD segments");
  if (!dynamic) return fail("no PT_DYNAMIC");

  base_ = static_cast<uint8_t*>(MapRW(static_cast<size_t>(span_)));
  if (!base_) return fail("cannot reserve image memory");
  traps_ = static_cast<uint8_t*>(MapGuard(kPageSize));
  if (!traps_) return fail("cannot reserve trap page");

  for (uint16_t i = 0; i < eh->phnum; ++i) {
    if (ph[i].type != PT_LOAD) continue;
    if (ph[i].offset + ph[i].filesz > file.size()) return fail("segment past EOF");
    memcpy(base_ + ph[i].vaddr, file.data() + ph[i].offset,
           static_cast<size_t>(ph[i].filesz));
    // The memsz > filesz tail (.bss) is already zero from a fresh mapping.
  }

  // The program headers sit inside the first PT_LOAD, so they are addressable
  // in the mapped image once the segments are copied.
  phdrs_ = base_ + eh->phoff;
  phnum_ = eh->phnum;

  // --- .dynamic ------------------------------------------------------------
  const Dyn* dyn = reinterpret_cast<const Dyn*>(base_ + dynamic->vaddr);
  uint64_t rela = 0, relasz = 0, jmprel = 0, pltrelsz = 0;
  uint64_t init_arr = 0, init_sz = 0, verneed = 0, verneednum = 0, hash = 0;
  std::vector<uint32_t> needed_offsets;
  for (; dyn->tag != 0; ++dyn) {
    switch (dyn->tag) {
      case DT_NEEDED:
        needed_offsets.push_back(static_cast<uint32_t>(dyn->val));
        break;
      case DT_STRTAB: strtab_ = reinterpret_cast<const char*>(base_ + dyn->val); break;
      case DT_SYMTAB: symtab_ = base_ + dyn->val; break;
      case DT_HASH: hash = dyn->val; break;
      case DT_VERSYM:
        versym_ = reinterpret_cast<const uint16_t*>(base_ + dyn->val);
        break;
      case DT_VERNEED: verneed = dyn->val; break;
      case DT_VERNEEDNUM: verneednum = dyn->val; break;
      case DT_RELA: rela = dyn->val; break;
      case DT_RELASZ: relasz = dyn->val; break;
      case DT_JMPREL: jmprel = dyn->val; break;
      case DT_PLTRELSZ: pltrelsz = dyn->val; break;
      case DT_INIT_ARRAY: init_arr = dyn->val; break;
      case DT_INIT_ARRAYSZ: init_sz = dyn->val; break;
      default: break;
    }
  }
  if (!strtab_ || !symtab_) return fail("no DT_STRTAB / DT_SYMTAB");
  for (uint32_t off : needed_offsets) needed_.push_back(strtab_ + off);

  // DT_SYMTAB carries no count; the SysV hash nchain field is the symbol count.
  if (hash) symcount_ = reinterpret_cast<const uint32_t*>(base_ + hash)[1];

  // Version index -> the library filename that provides it, so unresolved
  // imports can be grouped by the shim that owes them.
  if (verneed && verneednum) {
    verneed_.assign(64, "");
    const uint8_t* p = base_ + verneed;
    for (uint64_t i = 0; i < verneednum; ++i) {
      const Verneed* vn = reinterpret_cast<const Verneed*>(p);
      const char* provider = strtab_ + vn->file;
      const uint8_t* a = p + vn->aux;
      for (uint16_t j = 0; j < vn->cnt; ++j) {
        const Vernaux* vna = reinterpret_cast<const Vernaux*>(a);
        uint16_t idx = vna->other & 0x7fff;
        if (idx >= verneed_.size()) verneed_.resize(idx + 1, "");
        verneed_[idx] = provider;
        if (!vna->next) break;
        a += vna->next;
      }
      if (!vn->next) break;
      p += vn->next;
    }
  }

  // --- relocations ---------------------------------------------------------
  auto apply = [&](uint64_t off, uint64_t size) -> bool {
    const Rela* r = reinterpret_cast<const Rela*>(base_ + off);
    for (uint64_t i = 0; i < size / sizeof(Rela); ++i, ++r) {
      uint32_t type = static_cast<uint32_t>(r->info);
      uint32_t sym = static_cast<uint32_t>(r->info >> 32);
      uint64_t* slot = reinterpret_cast<uint64_t*>(base_ + r->offset);
      switch (type) {
        case R_AARCH64_RELATIVE:
          *slot = reinterpret_cast<uint64_t>(base_) + r->addend;
          break;
        case R_AARCH64_ABS64:
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
          *slot = SymbolValue(sym, resolve) + r->addend;
          break;
        default: {
          char buf[80];
          snprintf(buf, sizeof(buf), "unhandled relocation type %u", type);
          if (err) *err = buf;
          return false;
        }
      }
      ++relocs_;
    }
    return true;
  };
  if (rela && !apply(rela, relasz)) return false;
  if (jmprel && !apply(jmprel, pltrelsz)) return false;

  if (init_arr) {
    const uint64_t* ia = reinterpret_cast<const uint64_t*>(base_ + init_arr);
    for (uint64_t i = 0; i < init_sz / 8; ++i) init_array_.push_back(ia[i]);
  }
  return true;
}

uint64_t ElfImage::Lookup(const char* name) const {
  // ponytail: linear over ~12.6k symbols, called ~14 times at startup.
  // Swap in DT_GNU_HASH if lookups ever land in a hot path.
  for (size_t i = 0; i < symcount_; ++i) {
    const Sym* s = reinterpret_cast<const Sym*>(symtab_ + i * sizeof(Sym));
    if (s->shndx != SHN_UNDEF && strcmp(strtab_ + s->name, name) == 0)
      return reinterpret_cast<uint64_t>(base_) + s->value;
  }
  return 0;
}

std::string ElfImage::SymbolAt(uint64_t addr, uint64_t* offset) const {
  const uint64_t origin = reinterpret_cast<uint64_t>(base_);
  if (!symtab_ || !strtab_ || addr < origin) return std::string();
  const uint64_t rel = addr - origin;
  const Sym* best = nullptr;
  for (size_t i = 0; i < symcount_; ++i) {
    const Sym* s = reinterpret_cast<const Sym*>(symtab_ + i * sizeof(Sym));
    if (s->shndx == SHN_UNDEF || (s->info & 0xf) != kSttFunc) continue;
    if (s->value > rel) continue;
    if (s->size && rel >= s->value + s->size) continue;
    // Nearest start wins. Plenty of symbols carry no size, and without this a
    // sizeless one would swallow every function laid out after it.
    if (!best || s->value > best->value) best = s;
  }
  if (!best) return std::string();
  if (offset) *offset = rel - best->value;
  return strtab_ + best->name;
}

std::vector<std::string> ElfImage::ExportsWithPrefix(const char* prefix) const {
  std::vector<std::string> out;
  const size_t n = strlen(prefix);
  for (size_t i = 0; i < symcount_; ++i) {
    const Sym* s = reinterpret_cast<const Sym*>(symtab_ + i * sizeof(Sym));
    const char* name = strtab_ + s->name;
    if (s->shndx != SHN_UNDEF && strncmp(name, prefix, n) == 0)
      out.push_back(name);
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

bool ElfImage::Protect(std::string* err) {
  for (const Segment& s : segments_) {
    uint64_t start = s.vaddr & ~(kPageSize - 1);
    uint64_t end = RoundUp(s.vaddr + s.memsz, kPageSize);
    if (!SetProtection(base_ + start, static_cast<size_t>(end - start), s.flags)) {
      if (err) *err = "failed to set segment protection";
      return false;
    }
  }
  return true;
}

}  // namespace arc
