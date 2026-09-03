// Sockets, dynamic linking, and the system calls a game reaches for on Android.
//
// Sockets are mostly a straight pass to the host: `struct sockaddr_in` has the
// same layout on Linux and Windows, so addresses cross unchanged. Two things do
// not, and both would corrupt silently rather than fail:
//
//   * `struct addrinfo`. Linux orders it ai_addrlen, ai_addr, ai_canonname;
//     Winsock orders it ai_addrlen, ai_canonname, ai_addr -- the two pointers
//     are swapped, and ai_addrlen is size_t rather than socklen_t. Passing one
//     through as the other hands the engine a canonical name where it expects
//     a sockaddr. So results are translated into guest-shaped nodes.
//
//   * `SOL_SOCKET` option numbers. SO_REUSEADDR is 2 on Linux and 4 on
//     Windows; SO_RCVTIMEO is 20 against 0x1006. Unmapped, a timeout request
//     silently sets something else.
//
// Everything a desktop port has no use for -- fork, signal delivery, syslog --
// is a stub that succeeds. Those are honest: they exist so the engine's error
// paths are not taken, not to pretend the behaviour was reproduced.

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#include "elf_image.h"
#include "shim.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <link.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace arc {
namespace {

// --- images, for dlsym and dl_iterate_phdr ---------------------------------
std::mutex g_images_lock;
std::vector<const ElfImage*> g_images;

// --- sockets ---------------------------------------------------------------

#if defined(_WIN32)
// Winsock needs starting, and nothing in the engine will do it for us.
void EnsureWinsock() {
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  });
}

constexpr int kGuestSolSocket = 1;
int TranslateSockopt(int level, int name) {
  if (level != kGuestSolSocket) return name;
  switch (name) {
    case 2: return SO_REUSEADDR;
    case 4: return SO_ERROR;
    case 7: return SO_SNDBUF;
    case 8: return SO_RCVBUF;
    case 9: return SO_KEEPALIVE;
    case 13: return SO_LINGER;
    case 20: return SO_RCVTIMEO;
    case 21: return SO_SNDTIMEO;
    default: return name;
  }
}
#else
void EnsureWinsock() {}
int TranslateSockopt(int, int name) { return name; }
#endif

int Socket(int domain, int type, int protocol) {
  EnsureWinsock();
  return static_cast<int>(::socket(domain, type, protocol));
}
int Bind(int fd, const void* addr, uint32_t len) {
  return ::bind(fd, static_cast<const sockaddr*>(addr), len);
}
int Connect(int fd, const void* addr, uint32_t len) {
  return ::connect(fd, static_cast<const sockaddr*>(addr), len);
}
int Listen(int fd, int backlog) { return ::listen(fd, backlog); }
int Accept(int fd, void* addr, uint32_t* len) {
  return static_cast<int>(
      ::accept(fd, static_cast<sockaddr*>(addr),
               reinterpret_cast<socklen_t*>(len)));
}
int64_t Send(int fd, const void* buf, uint64_t n, int flags) {
  return ::send(fd, static_cast<const char*>(buf), static_cast<int>(n), flags);
}
int64_t Recv(int fd, void* buf, uint64_t n, int flags) {
  return ::recv(fd, static_cast<char*>(buf), static_cast<int>(n), flags);
}
int64_t Sendto(int fd, const void* buf, uint64_t n, int flags,
               const void* addr, uint32_t len) {
  return ::sendto(fd, static_cast<const char*>(buf), static_cast<int>(n), flags,
                  static_cast<const sockaddr*>(addr), len);
}
int64_t Recvfrom(int fd, void* buf, uint64_t n, int flags, void* addr,
                 uint32_t* len) {
  return ::recvfrom(fd, static_cast<char*>(buf), static_cast<int>(n), flags,
                    static_cast<sockaddr*>(addr),
                    reinterpret_cast<socklen_t*>(len));
}
int Shutdown(int fd, int how) { return ::shutdown(fd, how); }
int Setsockopt(int fd, int level, int name, const void* val, uint32_t len) {
  return ::setsockopt(fd, level, TranslateSockopt(level, name),
                      static_cast<const char*>(val), len);
}
int Getsockopt(int fd, int level, int name, void* val, uint32_t* len) {
  return ::getsockopt(fd, level, TranslateSockopt(level, name),
                      static_cast<char*>(val),
                      reinterpret_cast<socklen_t*>(len));
}
int Getsockname(int fd, void* addr, uint32_t* len) {
  return ::getsockname(fd, static_cast<sockaddr*>(addr),
                       reinterpret_cast<socklen_t*>(len));
}
int Getpeername(int fd, void* addr, uint32_t* len) {
  return ::getpeername(fd, static_cast<sockaddr*>(addr),
                       reinterpret_cast<socklen_t*>(len));
}
int Gethostname(char* name, uint64_t len) {
  EnsureWinsock();
  return ::gethostname(name, static_cast<int>(len));
}
int Select(int n, void* r, void* w, void* e, void* timeout) {
  return ::select(n, static_cast<fd_set*>(r), static_cast<fd_set*>(w),
                  static_cast<fd_set*>(e), static_cast<timeval*>(timeout));
}
const char* InetNtop(int af, const void* src, char* dst, uint32_t size) {
  return ::inet_ntop(af, src, dst, size);
}
int InetPton(int af, const char* src, void* dst) {
  return ::inet_pton(af, src, dst);
}

// Bionic's addrinfo, in Bionic's order.
struct GuestAddrinfo {
  int32_t ai_flags;
  int32_t ai_family;
  int32_t ai_socktype;
  int32_t ai_protocol;
  uint32_t ai_addrlen;
  sockaddr* ai_addr;
  char* ai_canonname;
  GuestAddrinfo* ai_next;
};

void FreeGuestAddrinfo(GuestAddrinfo* list) {
  while (list) {
    GuestAddrinfo* next = list->ai_next;
    free(list->ai_addr);
    free(list->ai_canonname);
    free(list);
    list = next;
  }
}

int Getaddrinfo(const char* node, const char* service, const void* hints_in,
                GuestAddrinfo** out) {
  EnsureWinsock();
  // Hints share the leading four ints, which is all getaddrinfo reads from
  // them, so a fresh host-shaped hints struct is built from those.
  addrinfo hints{};
  const addrinfo* hints_ptr = nullptr;
  if (hints_in) {
    const auto* g = static_cast<const GuestAddrinfo*>(hints_in);
    hints.ai_flags = g->ai_flags;
    hints.ai_family = g->ai_family;
    hints.ai_socktype = g->ai_socktype;
    hints.ai_protocol = g->ai_protocol;
    hints_ptr = &hints;
  }

  addrinfo* host = nullptr;
  int rc = ::getaddrinfo(node, service, hints_ptr, &host);
  if (rc != 0) return rc;

  GuestAddrinfo* head = nullptr;
  GuestAddrinfo** tail = &head;
  for (addrinfo* h = host; h; h = h->ai_next) {
    auto* g = static_cast<GuestAddrinfo*>(calloc(1, sizeof(GuestAddrinfo)));
    g->ai_flags = h->ai_flags;
    g->ai_family = h->ai_family;
    g->ai_socktype = h->ai_socktype;
    g->ai_protocol = h->ai_protocol;
    g->ai_addrlen = static_cast<uint32_t>(h->ai_addrlen);
    if (h->ai_addr && h->ai_addrlen) {
      g->ai_addr = static_cast<sockaddr*>(malloc(h->ai_addrlen));
      memcpy(g->ai_addr, h->ai_addr, h->ai_addrlen);
    }
    if (h->ai_canonname) {
#if defined(_WIN32)
      g->ai_canonname = _strdup(h->ai_canonname);
#else
      g->ai_canonname = strdup(h->ai_canonname);
#endif
    }
    *tail = g;
    tail = &g->ai_next;
  }
  ::freeaddrinfo(host);
  *out = head;
  return 0;
}

void Freeaddrinfo(GuestAddrinfo* list) { FreeGuestAddrinfo(list); }

const char* GaiStrerror(int) { return "getaddrinfo error"; }
int Getnameinfo(const void*, uint32_t, char* host, uint32_t hostlen, char* serv,
                uint32_t servlen, int) {
  if (host && hostlen) host[0] = '\0';
  if (serv && servlen) serv[0] = '\0';
  return 0;
}
void* Gethostbyname(const char*) { return nullptr; }
unsigned IfNametoindex(const char*) { return 0; }
int Socketpair(int, int, int, int*) { return -1; }
int64_t Sendfile(int, int, void*, uint64_t) { return -1; }
int Poll(void*, unsigned long, int) { return 0; }
int Ioctl(int, unsigned long, ...) { return 0; }

// --- dynamic linking -------------------------------------------------------
// dlopen returns null: every library the engine needs is already mapped, and a
// runtime load of an Android system library could not be satisfied anyway.
// dlsym searches the images we loaded, then the shim, which is what makes a
// dlsym-based GL or extension probe work.

void* Dlopen(const char*, int) { return nullptr; }
int Dlclose(void*) { return 0; }
const char* Dlerror() { return nullptr; }

void* Dlsym(void*, const char* symbol) {
  {
    std::lock_guard<std::mutex> g(g_images_lock);
    for (const ElfImage* img : g_images)
      if (uint64_t a = img->Lookup(symbol)) return reinterpret_cast<void*>(a);
  }
  return reinterpret_cast<void*>(ShimResolve(symbol));
}

// The C++ unwinder walks this to find each image's .eh_frame, so exceptions
// depend on it reporting the images we mapped. Bionic's dl_phdr_info leads
// with the fields the unwinder reads.
struct GuestPhdrInfo {
  uint64_t dlpi_addr;
  const char* dlpi_name;
  const void* dlpi_phdr;
  uint16_t dlpi_phnum;
};

int DlIteratePhdr(int (*callback)(GuestPhdrInfo*, uint64_t, void*), void* data) {
  std::vector<const ElfImage*> images;
  {
    std::lock_guard<std::mutex> g(g_images_lock);
    images = g_images;
  }
  for (const ElfImage* img : images) {
    GuestPhdrInfo info{};
    info.dlpi_addr = reinterpret_cast<uint64_t>(img->base());
    info.dlpi_name = "";
    info.dlpi_phdr = img->phdrs();
    info.dlpi_phnum = static_cast<uint16_t>(img->phnum());
    int rc = callback(&info, sizeof(info), data);
    if (rc != 0) return rc;
  }
  return 0;
}

// --- process and system ----------------------------------------------------

int Getpid() {
#if defined(_WIN32)
  return static_cast<int>(GetCurrentProcessId());
#else
  return ::getpid();
#endif
}
int Gettid() {
#if defined(_WIN32)
  return static_cast<int>(GetCurrentThreadId());
#else
  return static_cast<int>(::syscall(186));
#endif
}
int Geteuid() { return 0; }
int Getpwuid_r(uint32_t, void*, char*, uint64_t, void** result) {
  if (result) *result = nullptr;
  return 0;
}
int64_t Sysconf(int name) {
  // _SC_PAGESIZE (39) and _SC_NPROCESSORS_ONLN (97) on Bionic.
  if (name == 39) return 4096;
  if (name == 97) return 8;
  return -1;
}
uint64_t Getauxval(uint64_t) { return 0; }
int64_t Syscall(int64_t, ...) { return -1; }
int Uname(void* buf) {
  // Linux struct utsname: six 65-byte fields. Zeroed is a valid answer.
  if (buf) memset(buf, 0, 6 * 65);
  return 0;
}
int Fork() { return -1; }
int Execl(const char*, ...) { return -1; }
int Waitpid(int, int*, int) { return -1; }
int Kill(int, int) { return 0; }
void Openlog(const char*, int, int) {}
void Closelog() {}
void Syslog(int, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}
void AndroidSetAbortMessage(const char* msg) {
  fprintf(stderr, "abort: %s\n", msg ? msg : "");
}

// Signal delivery has no desktop counterpart worth reproducing: the host
// process is not going to receive SIGPIPE from a loopback socket, and the
// engine's handlers exist for Android's process lifecycle.
int Sigaction(int, const void*, void*) { return 0; }
int Sigaddset(void*, int) { return 0; }
int Sigdelset(void*, int) { return 0; }
int Sigemptyset(void*) { return 0; }
int Sigfillset(void*) { return 0; }
int Sigprocmask(int, const void*, void*) { return 0; }
[[noreturn]] void Siglongjmp(void*, int) {
  fprintf(stderr, "siglongjmp -- not implemented\n");
  abort();
}
void FdSetChk(int, void*, uint64_t) {}
int FdIssetChk(int, const void*, uint64_t) { return 0; }

// POSIX regex and fts. Nothing on a game's hot path uses these; they exist so
// the engine's rarely-taken diagnostic paths link.
int Regcomp(void*, const char*, int) { return -1; }
int Regexec(const void*, const char*, uint64_t, void*, int) { return 1; }
uint64_t Regerror(int, const void*, char* buf, uint64_t n) {
  if (buf && n) buf[0] = '\0';
  return 0;
}
void Regfree(void*) {}
void* FtsOpen(char* const*, int, void*) { return nullptr; }
void* FtsRead(void*) { return nullptr; }
int FtsClose(void*) { return 0; }
int Fnmatch(const char*, const char*, int) { return 1; }

long Random() { return rand(); }
void Srand48(long seed) { srand(static_cast<unsigned>(seed)); }

// --- libjnigraphics --------------------------------------------------------
// A bitmap on the Java side. Nothing hands us one on desktop, so these fail
// cleanly rather than pretending a lock succeeded and returning a wild pointer.
int AndroidBitmapGetInfo(void*, void*, void*) { return -1; }
int AndroidBitmapLockPixels(void*, void*, void** pixels) {
  if (pixels) *pixels = nullptr;
  return -1;
}
int AndroidBitmapUnlockPixels(void*, void*) { return -1; }

struct Entry {
  const char* name;
  void* fn;
};

#define E(sym, fn) {sym, reinterpret_cast<void*>(&fn)}
const Entry kTable[] = {
    E("socket", Socket),            E("bind", Bind),
    E("connect", Connect),          E("listen", Listen),
    E("accept", Accept),            E("send", Send),
    E("recv", Recv),                E("sendto", Sendto),
    E("recvfrom", Recvfrom),        E("shutdown", Shutdown),
    E("setsockopt", Setsockopt),    E("getsockopt", Getsockopt),
    E("getsockname", Getsockname),  E("getpeername", Getpeername),
    E("gethostname", Gethostname),  E("select", Select),
    E("inet_ntop", InetNtop),       E("inet_pton", InetPton),
    E("getaddrinfo", Getaddrinfo),  E("freeaddrinfo", Freeaddrinfo),
    E("gai_strerror", GaiStrerror), E("getnameinfo", Getnameinfo),
    E("gethostbyname", Gethostbyname),
    E("if_nametoindex", IfNametoindex),
    E("socketpair", Socketpair),    E("sendfile", Sendfile),
    E("poll", Poll),                E("ioctl", Ioctl),

    E("dlopen", Dlopen),            E("dlsym", Dlsym),
    E("dlclose", Dlclose),          E("dlerror", Dlerror),
    E("dl_iterate_phdr", DlIteratePhdr),

    E("getpid", Getpid),            E("gettid", Gettid),
    E("geteuid", Geteuid),          E("getpwuid_r", Getpwuid_r),
    E("sysconf", Sysconf),          E("getauxval", Getauxval),
    E("syscall", Syscall),          E("uname", Uname),
    E("fork", Fork),                E("execl", Execl),
    E("waitpid", Waitpid),          E("kill", Kill),
    E("openlog", Openlog),          E("closelog", Closelog),
    E("syslog", Syslog),
    E("android_set_abort_message", AndroidSetAbortMessage),

    E("sigaction", Sigaction),      E("sigaddset", Sigaddset),
    E("sigdelset", Sigdelset),      E("sigemptyset", Sigemptyset),
    E("sigfillset", Sigfillset),    E("sigprocmask", Sigprocmask),
    E("siglongjmp", Siglongjmp),
    E("__FD_SET_chk", FdSetChk),    E("__FD_ISSET_chk", FdIssetChk),

    E("regcomp", Regcomp),          E("regexec", Regexec),
    E("regerror", Regerror),        E("regfree", Regfree),
    E("fts_open", FtsOpen),         E("fts_read", FtsRead),
    E("fts_close", FtsClose),       E("fnmatch", Fnmatch),
    E("random", Random),            E("srand48", Srand48),

    E("AndroidBitmap_getInfo", AndroidBitmapGetInfo),
    E("AndroidBitmap_lockPixels", AndroidBitmapLockPixels),
    E("AndroidBitmap_unlockPixels", AndroidBitmapUnlockPixels),
};
#undef E

}  // namespace

void ShimRegisterImage(const ElfImage* image) {
  std::lock_guard<std::mutex> g(g_images_lock);
  g_images.push_back(image);
}

uint64_t ShimResolveSys(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimSysCount() { return sizeof(kTable) / sizeof(kTable[0]); }

}  // namespace arc
