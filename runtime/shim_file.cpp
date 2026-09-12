// File I/O, directories and memory mapping.
//
// This is the layer where an Android ABI actually has to be reproduced rather
// than forwarded. The host has `open`, `stat` and `readdir` too, but they are
// not the same functions: Bionic's `O_CREAT` is 0100 and the Microsoft CRT's is
// 0x100, and Bionic's `struct stat` and `struct dirent` have layouts of their
// own. The engine allocated those structs and reads the fields back at fixed
// offsets, so we fill them field by field at Bionic's offsets instead of
// letting the host write its own shape into them.
//
// The struct layouts below are the Linux arm64 kernel ABI, which Bionic uses
// unchanged. They are stable and public, but they are also the highest-risk
// thing in this file: if file operations misbehave in a way that looks like
// garbage sizes or modes, `GuestStat` is the first place to look.
//
// Descriptors are the host's own, because every call that consumes one routes
// through this file.

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <random>
#include <set>
#include <string>

#include <map>
#include "shim.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace arc {
namespace {

// --- Bionic / Linux arm64 ABI ----------------------------------------------

struct GuestTimespec {
  int64_t tv_sec;
  int64_t tv_nsec;
};

struct GuestStat {
  uint64_t st_dev;
  uint64_t st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint64_t __pad1;
  int64_t st_size;
  int32_t st_blksize;
  int32_t __pad2;
  int64_t st_blocks;
  GuestTimespec st_atim;
  GuestTimespec st_mtim;
  GuestTimespec st_ctim;
  uint32_t __unused4;
  uint32_t __unused5;
};
static_assert(sizeof(GuestStat) == 128, "Linux arm64 struct stat is 128 bytes");

struct GuestDirent {
  uint64_t d_ino;
  int64_t d_off;
  uint16_t d_reclen;
  uint8_t d_type;
  char d_name[256];
};

constexpr uint32_t kGuestIfmt = 0170000;
constexpr uint32_t kGuestIfreg = 0100000;
constexpr uint32_t kGuestIfdir = 0040000;
constexpr uint8_t kGuestDtDir = 4;
constexpr uint8_t kGuestDtReg = 8;

// Bionic's open flags are octal Linux values and share only the low two bits
// with the Microsoft CRT's. Translating them is not optional: passing Bionic's
// O_CREAT (64) straight to _open sets _O_APPEND|... and silently does the wrong
// thing rather than failing.
constexpr int kGuestOCreat = 0100;
constexpr int kGuestOExcl = 0200;
constexpr int kGuestOTrunc = 01000;
constexpr int kGuestOAppend = 02000;

int TranslateOpenFlags(int guest_flags) {
#if defined(_WIN32)
  int host = guest_flags & 3;  // RDONLY/WRONLY/RDWR agree
  if (guest_flags & kGuestOCreat) host |= _O_CREAT;
  if (guest_flags & kGuestOExcl) host |= _O_EXCL;
  if (guest_flags & kGuestOTrunc) host |= _O_TRUNC;
  if (guest_flags & kGuestOAppend) host |= _O_APPEND;
  // Android has no text mode; a translated newline would corrupt assets.
  return host | _O_BINARY;
#else
  return guest_flags;
#endif
}

#if defined(_WIN32)
void FillStat(const struct __stat64& in, GuestStat* out) {
  memset(out, 0, sizeof(*out));
  out->st_dev = in.st_dev;
  out->st_ino = in.st_ino;
  out->st_nlink = in.st_nlink;
  out->st_uid = in.st_uid;
  out->st_gid = in.st_gid;
  out->st_rdev = in.st_rdev;
  out->st_size = in.st_size;
  out->st_blksize = 4096;
  out->st_blocks = (in.st_size + 511) / 512;
  out->st_atim.tv_sec = in.st_atime;
  out->st_mtim.tv_sec = in.st_mtime;
  out->st_ctim.tv_sec = in.st_ctime;
  // The CRT reports _S_IFDIR/_S_IFREG, which happen to match Linux's values,
  // but the permission bits do not survive: synthesise something sane.
  out->st_mode = (in.st_mode & _S_IFDIR) ? (kGuestIfdir | 0755)
                                         : (kGuestIfreg | 0644);
}
#endif

// Which paths the engine actually asks for, and whether they were there. A
// title that cannot find its own files says so in its own words much later, if
// at all -- and by then the name it looked for is the one thing missing from
// the account.
bool TracingFiles() {
  static const bool on = getenv("ARC_TRACE_FILES") != nullptr;
  return on;
}

void TraceFile(const char* what, const char* path, bool found) {
  if (TracingFiles())
    fprintf(stderr, "[file] %-8s %-5s %s\n", what, found ? "ok" : "MISS",
            path ? path : "(null)");
}

// Which file a stream is, so that closing it can be traced by name.
//
// A trace of opens with no closes answers "did it find the file" and nothing
// about lifetime, which is the question when a fault looks like something
// reading through a handle another part of the engine has already let go.
// Only kept while tracing: otherwise it is a map insertion per fopen for
// nobody's benefit.
std::mutex g_open_lock;
std::map<FILE*, std::string> g_open_paths;

void RememberOpen(FILE* f, const char* path) {
  if (!TracingFiles() || !f) return;
  std::lock_guard<std::mutex> held(g_open_lock);
  g_open_paths[f] = path ? path : "(null)";
}

void TraceCloseImpl(FILE* f) {
  if (!TracingFiles()) return;
  std::string path = "(never opened here)";
  {
    std::lock_guard<std::mutex> held(g_open_lock);
    auto it = g_open_paths.find(f);
    if (it != g_open_paths.end()) {
      path = it->second;
      g_open_paths.erase(it);
    }
  }
  fprintf(stderr, "[file] %-8s %-5s %s\n", "fclose", "ok", path.c_str());
}

}  // namespace

// fclose lives in the posix half of the shim; the map of open paths lives
// here, next to fopen that fills it.
void ShimTraceClose(void* stream) {
  TraceCloseImpl(static_cast<FILE*>(stream));
}

namespace {

int StatPath(const char* path, GuestStat* out) {
#if defined(_WIN32)
  struct __stat64 st;
  if (_stat64(path, &st) != 0) return -1;
  FillStat(st, out);
  return 0;
#else
  struct stat st;
  if (::stat(path, &st) != 0) return -1;
  memset(out, 0, sizeof(*out));
  out->st_mode = st.st_mode;
  out->st_size = st.st_size;
  out->st_ino = st.st_ino;
  out->st_nlink = st.st_nlink;
  out->st_blksize = st.st_blksize;
  out->st_blocks = st.st_blocks;
  out->st_mtim.tv_sec = st.st_mtime;
  return 0;
#endif
}

int Stat(const char* path, GuestStat* out) {
  const int rc = StatPath(path, out);
  TraceFile("stat", path, rc == 0);
  return rc;
}
int Lstat(const char* path, GuestStat* out) { return Stat(path, out); }

int Fstat(int fd, GuestStat* out) {
#if defined(_WIN32)
  struct __stat64 st;
  if (_fstat64(fd, &st) != 0) return -1;
  FillStat(st, out);
  return 0;
#else
  struct stat st;
  if (::fstat(fd, &st) != 0) return -1;
  memset(out, 0, sizeof(*out));
  out->st_mode = st.st_mode;
  out->st_size = st.st_size;
  out->st_blksize = st.st_blksize;
  return 0;
#endif
}

// `/dev/urandom` is not a file to be translated; it is the interface to the
// system's entropy, and the host has its own. Without it the C++ runtime's
// std::random_device throws out of a *static initialiser* -- so the engine
// terminates before anything runs, and the only clue is an abort message
// several frames into the terminate handler. Worth an explicit answer.
constexpr int kRandomFd = 0x7000000;

bool IsRandomDevice(const char* path) {
  return path && (strcmp(path, "/dev/urandom") == 0 ||
                  strcmp(path, "/dev/random") == 0);
}

void FillRandom(void* buf, size_t n) {
  static std::mutex lock;
  static std::random_device source;
  std::lock_guard<std::mutex> held(lock);
  auto* out = static_cast<unsigned char*>(buf);
  size_t i = 0;
  while (i < n) {
    const unsigned int bits = source();
    for (size_t b = 0; b < sizeof(bits) && i < n; ++b, ++i)
      out[i] = static_cast<unsigned char>(bits >> (b * 8));
  }
}

// fopen is the other door onto the same problem the flags above solve, and it
// was left standing open. Bionic has no text mode, so a title writes "r" and
// means "rb"; the UCRT takes "r" literally, drops every 0x0D that precedes a
// 0x0A and stops at the first 0x1A. A pack file read that way comes back
// shorter than it is with holes in the middle -- which does not fail, it
// decodes to an image 0 pixels wide, uploads cleanly, and draws nothing.
FILE* Fopen(const char* path, const char* mode) {
  char binary[8] = {0};
  size_t n = 0;
  bool has_b = false;
  for (const char* m = mode ? mode : "r"; *m && n < sizeof binary - 2; ++m) {
    if (*m == 'b') has_b = true;
    binary[n++] = *m;
  }
  if (!has_b) binary[n++] = 'b';
  FILE* f = fopen(path, binary);
  TraceFile("fopen", path, f != nullptr);
  RememberOpen(f, path);
  return f;
}

FILE* Freopen(const char* path, const char* mode, FILE* stream) {
  char binary[8] = {0};
  size_t n = 0;
  bool has_b = false;
  for (const char* m = mode ? mode : "r"; *m && n < sizeof binary - 2; ++m) {
    if (*m == 'b') has_b = true;
    binary[n++] = *m;
  }
  if (!has_b) binary[n++] = 'b';
  FILE* f = freopen(path, binary, stream);
  TraceFile("freopen", path, f != nullptr);
  return f;
}

int Open(const char* path, int flags, ...) {
  if (IsRandomDevice(path)) return kRandomFd;
#if defined(_WIN32)
  const int fd = _open(path, TranslateOpenFlags(flags), _S_IREAD | _S_IWRITE);
#else
  const int fd = ::open(path, flags, 0644);
#endif
  TraceFile("open", path, fd >= 0);
  return fd;
}
int Open2(const char* path, int flags) { return Open(path, flags); }

#if defined(_WIN32)
// On Linux a socket is a file descriptor and read()/write()/close() work on it.
// On Windows a SOCKET is a different namespace entirely, and the CRT's _read
// on one fails with EBADF -- so an HTTP client that opens a connection, sends
// its request and reads the reply gets a connection it can never read from.
// Nothing reports that as a network error; the caller just times out.
//
// Asking Winsock for the socket type is the cheap way to tell the two apart:
// it answers for a socket and fails for anything else.
//
// ponytail: this assumes a CRT descriptor is never also a valid SOCKET value.
// They are separate namespaces and small descriptors are not socket handles in
// practice, but the two could collide. Keep a set of the descriptors the socket
// shim handed out if that ever bites.
// Sockets the guest has asked to be non-blocking; see Fcntl below.
std::mutex g_nonblock_lock;
std::set<int> g_nonblock;

bool IsSocket(int fd) {
  int type = 0;
  int len = sizeof type;
  return ::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_TYPE,
                      reinterpret_cast<char*>(&type), &len) == 0;
}
#endif

int Close(int fd) {
  if (fd == kRandomFd) return 0;
#if defined(_WIN32)
  if (IsSocket(fd)) {
    {
      std::lock_guard<std::mutex> g(g_nonblock_lock);
      g_nonblock.erase(fd);
    }
    return ::closesocket(static_cast<SOCKET>(fd));
  }
  return _close(fd);
#else
  return ::close(fd);
#endif
}
int64_t Read(int fd, void* buf, uint64_t n) {
  if (fd == kRandomFd) {
    FillRandom(buf, static_cast<size_t>(n));
    return static_cast<int64_t>(n);
  }
#if defined(_WIN32)
  if (IsSocket(fd)) {
    const int rc = ::recv(static_cast<SOCKET>(fd), static_cast<char*>(buf),
                          static_cast<int>(n), 0);
    if (rc < 0) ShimNetErrno();
    return rc;
  }
  return _read(fd, buf, static_cast<unsigned>(n));
#else
  return ::read(fd, buf, n);
#endif
}
int64_t ReadChk(int fd, void* buf, uint64_t n, uint64_t) {
  return Read(fd, buf, n);
}
int64_t Write(int fd, const void* buf, uint64_t n) {
#if defined(_WIN32)
  if (IsSocket(fd)) {
    const int rc = ::send(static_cast<SOCKET>(fd), static_cast<const char*>(buf),
                          static_cast<int>(n), 0);
    if (rc < 0) ShimNetErrno();
    return rc;
  }
  return _write(fd, buf, static_cast<unsigned>(n));
#else
  return ::write(fd, buf, n);
#endif
}
int64_t Lseek(int fd, int64_t off, int whence) {
#if defined(_WIN32)
  return _lseeki64(fd, off, whence);
#else
  return ::lseek(fd, off, whence);
#endif
}

int Access(const char* path, int mode) {
#if defined(_WIN32)
  // Bionic's X_OK (1) has no Windows meaning and _access rejects it.
  return _access(path, mode == 1 ? 0 : mode);
#else
  return ::access(path, mode);
#endif
}

// Every component, not just the last one. Both the CRT's _mkdir and POSIX's
// mkdir fail when a parent is missing, and a title asks for the whole path at
// once -- on Android its data directory is built by the framework before any
// native code runs, so the engine has never had to make the parents itself.
// Here nothing built them, so the single-level call fails, the engine believes
// the directory exists because we said the request succeeded, and the first
// file it writes there cannot be opened.
int Mkdir(const char* path, uint32_t) {
  if (!path || !*path) return -1;
  std::error_code ec;
  // Already there is success: mkdir -p semantics, because the caller wants the
  // directory to exist rather than to have been the one that made it.
  if (std::filesystem::is_directory(path, ec)) return 0;
  std::filesystem::create_directories(path, ec);
  return ec ? -1 : 0;
}
int Rmdir(const char* path) {
#if defined(_WIN32)
  return _rmdir(path);
#else
  return ::rmdir(path);
#endif
}
int Chdir(const char* path) {
#if defined(_WIN32)
  return _chdir(path);
#else
  return ::chdir(path);
#endif
}
char* Getcwd(char* buf, uint64_t n) {
#if defined(_WIN32)
  return _getcwd(buf, static_cast<int>(n));
#else
  return ::getcwd(buf, n);
#endif
}
int Ftruncate(int fd, int64_t len) {
#if defined(_WIN32)
  return _chsize_s(fd, len);
#else
  return ::ftruncate(fd, len);
#endif
}
int Truncate(const char* path, int64_t len) {
  int fd = Open(path, 1 /* O_WRONLY */);
  if (fd < 0) return -1;
  int r = Ftruncate(fd, len);
  Close(fd);
  return r;
}
int Dup2(int a, int b) {
#if defined(_WIN32)
  return _dup2(a, b);
#else
  return ::dup2(a, b);
#endif
}
int Fsync(int fd) {
#if defined(_WIN32)
  return _commit(fd);
#else
  return ::fsync(fd);
#endif
}
char* Realpath(const char* path, char* resolved) {
#if defined(_WIN32)
  return _fullpath(resolved, path, 260);
#else
  return ::realpath(path, resolved);
#endif
}

// Permission and ownership have no Windows counterpart worth emulating, and
// nothing in a game port depends on them succeeding.
int Chmod(const char*, uint32_t) { return 0; }
int Fchmod(int, uint32_t) { return 0; }
int Fchmodat(int, const char*, uint32_t, int) { return 0; }
int Fchown(int, uint32_t, uint32_t) { return 0; }
// fcntl was a stub returning success for everything, and that is the one
// answer it must not give. An HTTP stack opens a socket, sets O_NONBLOCK, and
// then connects expecting -1/EINPROGRESS and a writability wait. Reporting
// success while leaving the socket blocking makes connect return 0 instead,
// the stack sees a state its non-blocking path does not have, and it closes
// the socket and tries the next address -- forever, without ever sending a
// byte. From outside it looks exactly like a network that is down.
//
// Only the file-status flags are real, and only for sockets, because Winsock
// is the only thing here with a switch to throw. Windows cannot read the flag
// back, so F_GETFL answers from what we were last told.
constexpr int kGuestFGetfd = 1;
constexpr int kGuestFSetfd = 2;
constexpr int kGuestFGetfl = 3;
constexpr int kGuestFSetfl = 4;
constexpr int kGuestONonblock = 0x800;
constexpr int kGuestORdwr = 2;

bool SetNonblocking(int fd, bool on) {
#if defined(_WIN32)
  u_long mode = on ? 1 : 0;
  if (::ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &mode) != 0) {
    ShimNetErrno();
    return false;
  }
  std::lock_guard<std::mutex> g(g_nonblock_lock);
  if (on) g_nonblock.insert(fd);
  else g_nonblock.erase(fd);
  return true;
#else
  const int flags = ::fcntl(fd, F_GETFL, 0);
  return ::fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK)
                                 : (flags & ~O_NONBLOCK)) == 0;
#endif
}

int Fcntl(int fd, int cmd, ...) {
#if defined(_WIN32)
  if (cmd == kGuestFGetfl || cmd == kGuestFSetfl) {
    if (!IsSocket(fd)) return cmd == kGuestFGetfl ? kGuestORdwr : 0;
    if (cmd == kGuestFGetfl) {
      std::lock_guard<std::mutex> g(g_nonblock_lock);
      return kGuestORdwr | (g_nonblock.count(fd) ? kGuestONonblock : 0);
    }
    va_list ap;
    va_start(ap, cmd);
    const int flags = va_arg(ap, int);
    va_end(ap);
    return SetNonblocking(fd, (flags & kGuestONonblock) != 0) ? 0 : -1;
  }
  // F_GETFD/F_SETFD are close-on-exec, and nothing here execs.
  if (cmd == kGuestFGetfd || cmd == kGuestFSetfd) return 0;
#else
  (void)fd;
  (void)cmd;
#endif
  return 0;
}
int Utimes(const char*, const void*) { return 0; }
int Utimensat(int, const char*, const void*, int) { return 0; }
int64_t Pathconf(const char*, int) { return -1; }
int Statvfs(const char*, void* buf) {
  if (buf) memset(buf, 0, 112);  // Linux arm64 struct statvfs
  return 0;
}
int Link(const char*, const char*) { return -1; }
int Symlink(const char*, const char*) { return -1; }
int64_t Readlink(const char*, char*, uint64_t) { return -1; }
int Pipe(int*) { return -1; }

// --- directories -----------------------------------------------------------
// The guest gets an opaque DIR* and a dirent laid out its way, so the host's
// own dirent never reaches it.

struct GuestDir {
#if defined(_WIN32)
  HANDLE find = INVALID_HANDLE_VALUE;
  WIN32_FIND_DATAA data{};
  bool pending = false;
#else
  DIR* dir = nullptr;
#endif
  GuestDirent entry{};
};

void* Opendir(const char* path) {
  if (!path || !*path) return nullptr;
  auto* d = new GuestDir();
#if defined(_WIN32)
  std::string pattern(path);
  while (!pattern.empty() &&
         (pattern.back() == '/' || pattern.back() == '\\'))
    pattern.pop_back();
  pattern += "\\*";
  d->find = FindFirstFileA(pattern.c_str(), &d->data);
  if (d->find == INVALID_HANDLE_VALUE) {
    TraceFile("opendir", path, false);
    delete d;
    return nullptr;
  }
  d->pending = true;
  TraceFile("opendir", path, true);
#else
  d->dir = ::opendir(path);
  if (!d->dir) {
    delete d;
    return nullptr;
  }
#endif
  return d;
}

void* Readdir(void* handle) {
  auto* d = static_cast<GuestDir*>(handle);
  if (!d) return nullptr;
#if defined(_WIN32)
  if (d->pending)
    d->pending = false;
  else if (!FindNextFileA(d->find, &d->data))
    return nullptr;
  const char* name = d->data.cFileName;
  d->entry.d_type = (d->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        ? kGuestDtDir
                        : kGuestDtReg;
#else
  struct dirent* e = ::readdir(d->dir);
  if (!e) return nullptr;
  const char* name = e->d_name;
  d->entry.d_type = e->d_type;
#endif
  size_t n = strlen(name);
  if (n >= sizeof(d->entry.d_name)) n = sizeof(d->entry.d_name) - 1;
  memcpy(d->entry.d_name, name, n);
  d->entry.d_name[n] = '\0';
  d->entry.d_reclen = static_cast<uint16_t>(sizeof(GuestDirent));
  return &d->entry;
}

int Closedir(void* handle) {
  auto* d = static_cast<GuestDir*>(handle);
  if (!d) return -1;
#if defined(_WIN32)
  if (d->find != INVALID_HANDLE_VALUE) FindClose(d->find);
#else
  if (d->dir) ::closedir(d->dir);
#endif
  delete d;
  return 0;
}

// --- memory ----------------------------------------------------------------
// ponytail: a file mapping is read into freshly allocated memory rather than
// mapped. Correct for the read-only asset loading this is used for, and wrong
// for MAP_SHARED writeback, which nothing here does. Revisit if a title
// actually shares a mapping.

constexpr int kGuestMapAnonymous = 0x20;
void* const kMapFailed = reinterpret_cast<void*>(-1);

void* Mmap(void* /*addr*/, uint64_t length, int /*prot*/, int flags, int fd,
           int64_t offset) {
#if defined(_WIN32)
  void* p = VirtualAlloc(nullptr, length, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE);
#else
  void* p = mmap(nullptr, length, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) p = nullptr;
#endif
  if (!p) return kMapFailed;
  if (!(flags & kGuestMapAnonymous) && fd >= 0) {
    Lseek(fd, offset, 0 /* SEEK_SET */);
    uint64_t got = 0;
    while (got < length) {
      int64_t n = Read(fd, static_cast<char*>(p) + got, length - got);
      if (n <= 0) break;
      got += static_cast<uint64_t>(n);
    }
  }
  return p;
}

int Munmap(void* addr, uint64_t) {
#if defined(_WIN32)
  return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
#else
  return munmap(addr, 0);
#endif
}

int Mprotect(void*, uint64_t, int) { return 0; }
void* Mremap(void*, uint64_t, uint64_t, int, ...) { return kMapFailed; }
int Madvise(void*, uint64_t, int) { return 0; }
int Mlock(const void*, uint64_t) { return 0; }
int Getpagesize() { return 4096; }

int PosixMemalign(void** out, uint64_t alignment, uint64_t size) {
#if defined(_WIN32)
  *out = _aligned_malloc(size, alignment);
#else
  if (posix_memalign(out, alignment, size) != 0) *out = nullptr;
#endif
  return *out ? 0 : 12 /* ENOMEM */;
}

struct Entry {
  const char* name;
  void* fn;
};

#define E(sym, fn) {sym, reinterpret_cast<void*>(&fn)}
const Entry kTable[] = {
    E("fopen", Fopen),        E("fopen64", Fopen),
    E("freopen", Freopen),    E("freopen64", Freopen),
    E("open", Open),          E("__open_2", Open2),
    E("close", Close),        E("read", Read),
    E("__read_chk", ReadChk), E("write", Write),
    E("lseek", Lseek),        E("lseek64", Lseek),
    E("stat", Stat),          E("lstat", Lstat),
    E("fstat", Fstat),        E("access", Access),
    E("mkdir", Mkdir),        E("rmdir", Rmdir),
    E("chdir", Chdir),        E("getcwd", Getcwd),
    E("ftruncate", Ftruncate), E("truncate", Truncate),
    E("dup2", Dup2),          E("fsync", Fsync),
    E("realpath", Realpath),  E("chmod", Chmod),
    E("fchmod", Fchmod),      E("fchmodat", Fchmodat),
    E("fchown", Fchown),      E("fcntl", Fcntl),
    E("utimes", Utimes),      E("utimensat", Utimensat),
    E("pathconf", Pathconf),  E("statvfs", Statvfs),
    E("link", Link),          E("symlink", Symlink),
    E("readlink", Readlink),  E("pipe", Pipe),

    E("opendir", Opendir),    E("readdir", Readdir),
    E("closedir", Closedir),

    E("mmap", Mmap),          E("munmap", Munmap),
    E("mprotect", Mprotect),  E("mremap", Mremap),
    E("madvise", Madvise),    E("mlock", Mlock),
    E("getpagesize", Getpagesize),
    E("posix_memalign", PosixMemalign),
};
#undef E

}  // namespace

// The same entropy the /dev/urandom stand-in uses, for callers outside this
// file: the syscall shim needs it for getrandom by number.
void ShimFillRandom(void* buf, size_t n) { FillRandom(buf, n); }

uint64_t ShimResolveFile(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimFileCount() { return sizeof(kTable) / sizeof(kTable[0]); }

}  // namespace arc
