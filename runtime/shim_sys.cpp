// Sockets, dynamic linking, and the system calls a game reaches for on Android.
//
// Sockets are mostly a straight pass to the host: `struct sockaddr_in` has the
// same layout on Linux and Windows, so addresses cross unchanged. Two things do
// not, and both would corrupt silently rather than fail:
//
//   * `struct addrinfo`. Bionic descends from NetBSD and orders it
//     ai_addrlen, ai_canonname, ai_addr; glibc swaps the two pointers, and
//     Winsock agrees with Bionic but makes ai_addrlen a size_t. Get the order
//     wrong and the engine is handed a canonical name where it expects a
//     sockaddr -- with no error, because the call still returns 0. So results
//     are translated into guest-shaped nodes.
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

#include "arm64_context.h"
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

// Address families and getaddrinfo flags, which Bionic spells with the Linux
// kernel's numbers and Winsock spells with its own.
//
// Only two of these actually differ, and both fail silently rather than
// loudly. AF_INET6 is 10 on Linux and 23 here, so a socket() for it is an
// unknown family and a getaddrinfo() hint of it matches nothing. AI_ADDRCONFIG
// is 0x20 on Linux and 0x400 here, and 0x20 here is not a flag at all --
// Winsock rejects the whole call with WSAEINVAL, so the name never resolves,
// the engine never opens a socket, and a title that checks for internet by
// resolving a well-known host decides it has none.
//
// The sockaddr the call returns carries the family too, in its first two
// bytes, so that is translated on the way back and on the way in.
constexpr int kGuestAfInet6 = 10;

int FamilyToHost(int family) {
#if defined(_WIN32)
  return family == kGuestAfInet6 ? AF_INET6 : family;
#else
  return family;
#endif
}

int FamilyToGuest(int family) {
#if defined(_WIN32)
  return family == AF_INET6 ? kGuestAfInet6 : family;
#else
  return family;
#endif
}

#if defined(_WIN32)
// Bionic's AI_* bits, from the Linux headers.
constexpr int kGuestAiPassive = 0x0001;
constexpr int kGuestAiCanonname = 0x0002;
constexpr int kGuestAiNumerichost = 0x0004;
constexpr int kGuestAiV4mapped = 0x0008;
constexpr int kGuestAiAll = 0x0010;
constexpr int kGuestAiAddrconfig = 0x0020;
constexpr int kGuestAiNumericserv = 0x0400;
#endif

int AiFlagsToHost(int flags) {
#if defined(_WIN32)
  int out = 0;
  if (flags & kGuestAiPassive) out |= AI_PASSIVE;
  if (flags & kGuestAiCanonname) out |= AI_CANONNAME;
  if (flags & kGuestAiNumerichost) out |= AI_NUMERICHOST;
  if (flags & kGuestAiV4mapped) out |= AI_V4MAPPED;
  if (flags & kGuestAiAll) out |= AI_ALL;
  if (flags & kGuestAiAddrconfig) out |= AI_ADDRCONFIG;
  if (flags & kGuestAiNumericserv) out |= AI_NUMERICSERV;
  return out;
#else
  return flags;
#endif
}

// A sockaddr the guest handed us, with its family in the host's terms. The
// copy is small and bounded; the alternative is writing into the guest's own
// structure, which it may well reuse.
struct HostSockaddr {
  alignas(8) unsigned char bytes[128];
  const sockaddr* get() const { return reinterpret_cast<const sockaddr*>(bytes); }
};

bool ToHostSockaddr(const void* addr, uint32_t len, HostSockaddr* out) {
  if (!addr || len < sizeof(uint16_t) || len > sizeof out->bytes) return false;
  memcpy(out->bytes, addr, len);
  uint16_t family = 0;
  memcpy(&family, out->bytes, sizeof family);
  family = static_cast<uint16_t>(FamilyToHost(family));
  memcpy(out->bytes, &family, sizeof family);
  return true;
}

void SockaddrToGuest(void* addr, uint32_t len) {
  if (!addr || len < sizeof(uint16_t)) return;
  uint16_t family = 0;
  memcpy(&family, addr, sizeof family);
  family = static_cast<uint16_t>(FamilyToGuest(family));
  memcpy(addr, &family, sizeof family);
}

int Socket(int domain, int type, int protocol) {
  EnsureWinsock();
  return static_cast<int>(::socket(FamilyToHost(domain), type, protocol));
}
int Bind(int fd, const void* addr, uint32_t len) {
  HostSockaddr host;
  if (!ToHostSockaddr(addr, len, &host)) return -1;
  return ::bind(fd, host.get(), static_cast<int>(len));
}
// Where the game's server actually is.
//
// A title built for Android has its server address compiled in and rewritten
// before installation -- for Tapped Out, by patching the library at an exact
// byte offset for an exact sha256. That is a workable answer when you are
// shipping an APK and a hopeless one when you are not: the offset is specific
// to one build, and a library that has already been patched once no longer
// contains the string anybody knows how to find.
//
// A native host does not have to play that game. ARC_SERVER_REDIRECT names an
// address, and every outbound connection that is not already loopback goes
// there instead. The engine keeps believing whatever URL it was built with;
// the connection lands on the sidecar.
//
// Deliberately not a hostname map: the point is to catch connections whose
// destination we could not name in advance, which is the whole problem.
//
// ponytail: it redirects everything, which is too much. A title that checks for
// internet by fetching a well-known https:// URL has that check sent to the
// sidecar too, and a plain-HTTP sidecar cannot answer a TLS handshake -- so the
// check fails and the title never gets as far as asking for its server. Narrow
// this to the destination port, or to everything except the check, once it is
// known which is which.
bool RedirectTarget(sockaddr_in* out) {
  static bool looked = false;
  static bool have = false;
  static sockaddr_in target{};
  if (!looked) {
    looked = true;
    const char* spec = getenv("ARC_SERVER_REDIRECT");
    if (spec && *spec) {
      char host[128] = {0};
      int port = 0;
      const char* colon = strrchr(spec, ':');
      const size_t n = colon ? static_cast<size_t>(colon - spec) : strlen(spec);
      if (n < sizeof host) {
        memcpy(host, spec, n);
        port = colon ? atoi(colon + 1) : 80;
        target.sin_family = AF_INET;
        target.sin_port = htons(static_cast<unsigned short>(port));
        if (::inet_pton(AF_INET, host, &target.sin_addr) == 1) have = true;
      }
      fprintf(stderr, "[net] redirecting outbound connections to %s\n",
              have ? spec : "(unparseable, ignored)");
    }
  }
  if (have) *out = target;
  return have;
}

// Loopback is left alone: a redirect that also catches the sidecar would send
// it to itself.
bool IsLoopback(const sockaddr* sa) {
  if (!sa || sa->sa_family != AF_INET) return false;
  const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
  return (ntohl(in->sin_addr.s_addr) >> 24) == 127;
}

int Connect(int fd, const void* addr, uint32_t len) {
  HostSockaddr host;
  if (!ToHostSockaddr(addr, len, &host)) return -1;
  sockaddr_in target{};
  if (RedirectTarget(&target) && !IsLoopback(host.get()))
    return ::connect(fd, reinterpret_cast<const sockaddr*>(&target),
                     static_cast<int>(sizeof target));
  return ::connect(fd, host.get(), static_cast<int>(len));
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
#if defined(_WIN32)
// A Linux fd_set is a bitmask indexed by descriptor; Winsock's is a count and
// an array. Translated both ways, because a caller reads back which of its
// descriptors are ready.
void GuestFdsToHost(const void* guest, int nfds, fd_set* host) {
  FD_ZERO(host);
  if (!guest) return;
  const auto* bits = static_cast<const uint64_t*>(guest);
  for (int fd = 0; fd < nfds && fd < 1024; ++fd)
    if (bits[fd / 64] & (uint64_t{1} << (fd % 64)))
      FD_SET(static_cast<SOCKET>(fd), host);
}

void HostFdsToGuest(const fd_set* host, void* guest, int nfds) {
  if (!guest) return;
  auto* bits = static_cast<uint64_t*>(guest);
  for (int i = 0; i < (nfds + 63) / 64 && i < 16; ++i) bits[i] = 0;
  for (u_int i = 0; i < host->fd_count; ++i) {
    const uint64_t fd = static_cast<uint64_t>(host->fd_array[i]);
    if (fd < 1024) bits[fd / 64] |= uint64_t{1} << (fd % 64);
  }
}
#endif

int Select(int n, void* r, void* w, void* e, void* timeout) {
#if defined(_WIN32)
  EnsureWinsock();
  fd_set hr, hw, he;
  GuestFdsToHost(r, n, &hr);
  GuestFdsToHost(w, n, &hw);
  GuestFdsToHost(e, n, &he);
  const int rc = ::select(n, r ? &hr : nullptr, w ? &hw : nullptr,
                          e ? &he : nullptr, static_cast<timeval*>(timeout));
  if (r) HostFdsToGuest(&hr, r, n);
  if (w) HostFdsToGuest(&hw, w, n);
  if (e) HostFdsToGuest(&he, e, n);
  return rc;
#else
  return ::select(n, static_cast<fd_set*>(r), static_cast<fd_set*>(w),
                  static_cast<fd_set*>(e), static_cast<timeval*>(timeout));
#endif
}
const char* InetNtop(int af, const void* src, char* dst, uint32_t size) {
  return ::inet_ntop(af, src, dst, size);
}
int InetPton(int af, const char* src, void* dst) {
  return ::inet_pton(af, src, dst);
}

// Bionic's addrinfo, in Bionic's order -- which is BSD's, not glibc's.
//
// This is the field order the file's own header comment got backwards. glibc
// puts ai_addr before ai_canonname; Bionic descends from NetBSD and puts
// ai_canonname first, which happens to be Winsock's order too. Built the glibc
// way, every resolution "succeeded" and handed the engine a canonical name
// where it expected a sockaddr -- so it never opened a socket, never
// connected, and decided it had no internet. There is no error anywhere in
// that sequence: the call returns 0 and the answer is furniture.
struct GuestAddrinfo {
  int32_t ai_flags;
  int32_t ai_family;
  int32_t ai_socktype;
  int32_t ai_protocol;
  uint32_t ai_addrlen;
  char* ai_canonname;
  sockaddr* ai_addr;
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
    hints.ai_flags = AiFlagsToHost(g->ai_flags);
    hints.ai_family = FamilyToHost(g->ai_family);
    hints.ai_socktype = g->ai_socktype;
    hints.ai_protocol = g->ai_protocol;
    hints_ptr = &hints;
  }

  addrinfo* host = nullptr;
  int rc = ::getaddrinfo(node, service, hints_ptr, &host);
  if (rc != 0) {
    // A name that will not resolve is the end of the road for whatever asked,
    // and the caller usually reports it as its own failure -- "no internet",
    // "cannot reach the server" -- with nothing saying which name or why.
    fprintf(stderr, "[net] getaddrinfo(%s, %s) failed: %d (flags=%#x fam=%d)\n",
            node ? node : "(null)", service ? service : "(null)", rc,
            hints_ptr ? hints_ptr->ai_flags : 0,
            hints_ptr ? hints_ptr->ai_family : -1);
    return rc;
  }

  GuestAddrinfo* head = nullptr;
  GuestAddrinfo** tail = &head;
  for (addrinfo* h = host; h; h = h->ai_next) {
    auto* g = static_cast<GuestAddrinfo*>(calloc(1, sizeof(GuestAddrinfo)));
    g->ai_flags = h->ai_flags;
    g->ai_family = FamilyToGuest(h->ai_family);
    g->ai_socktype = h->ai_socktype;
    g->ai_protocol = h->ai_protocol;
    g->ai_addrlen = static_cast<uint32_t>(h->ai_addrlen);
    if (h->ai_addr && h->ai_addrlen) {
      g->ai_addr = static_cast<sockaddr*>(malloc(h->ai_addrlen));
      memcpy(g->ai_addr, h->ai_addr, h->ai_addrlen);
      // The family lives in the sockaddr as well as in the addrinfo, and the
      // guest reads both.
      SockaddrToGuest(g->ai_addr, static_cast<uint32_t>(h->ai_addrlen));
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
// poll() and select(), which decide when a socket is ready and therefore
// whether anything on the network ever finishes.
//
// Neither could be forwarded. A `struct pollfd` is 8 bytes on Linux -- int fd,
// short events, short revents -- and 16 on Winsock, where the descriptor is a
// SOCKET; and the event bits share no values at all (Linux POLLIN is 0x001,
// Winsock's is 0x300). A Linux `fd_set` is a 1024-bit mask indexed by
// descriptor; Winsock's is a count followed by an array of descriptors.
//
// Poll was a stub returning 0, which says "nothing is ready" forever. That is
// not an error anyone reports: the engine's HTTP client connects, waits to be
// told the socket is readable, is never told, times out, and retries -- so a
// title sits on its loading screen looking like it has no network, having in
// fact opened the connection perfectly well.
constexpr short kGuestPollIn = 0x001;
constexpr short kGuestPollPri = 0x002;
constexpr short kGuestPollOut = 0x004;
constexpr short kGuestPollErr = 0x008;
constexpr short kGuestPollHup = 0x010;
constexpr short kGuestPollNval = 0x020;

struct GuestPollfd {
  int32_t fd;
  int16_t events;
  int16_t revents;
};

int Poll(void* fds_in, unsigned long nfds, int timeout) {
  auto* fds = static_cast<GuestPollfd*>(fds_in);
  if (!fds || nfds == 0) return 0;
#if defined(_WIN32)
  EnsureWinsock();
  std::vector<WSAPOLLFD> host(nfds);
  for (unsigned long i = 0; i < nfds; ++i) {
    host[i].fd = static_cast<SOCKET>(fds[i].fd);
    short e = 0;
    if (fds[i].events & kGuestPollIn) e |= POLLRDNORM;
    if (fds[i].events & kGuestPollPri) e |= POLLRDBAND;
    if (fds[i].events & kGuestPollOut) e |= POLLWRNORM;
    host[i].events = e;
    host[i].revents = 0;
  }
  const int rc = ::WSAPoll(host.data(), static_cast<ULONG>(nfds), timeout);
  for (unsigned long i = 0; i < nfds; ++i) {
    short r = 0;
    if (host[i].revents & (POLLRDNORM | POLLRDBAND)) r |= kGuestPollIn;
    if (host[i].revents & POLLWRNORM) r |= kGuestPollOut;
    if (host[i].revents & POLLERR) r |= kGuestPollErr;
    if (host[i].revents & POLLHUP) r |= kGuestPollHup;
    if (host[i].revents & POLLNVAL) r |= kGuestPollNval;
    fds[i].revents = r;
  }
  return rc;
#else
  return ::poll(reinterpret_cast<struct pollfd*>(fds), nfds, timeout);
#endif
}
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
    // A guest image's own symbol is guest code, and is deliberately *not*
    // announced as a native: the dispatcher would then call ARM instructions
    // as if they were host ones.
    for (const ElfImage* img : g_images)
      if (uint64_t a = img->Lookup(symbol)) return reinterpret_cast<void*>(a);
  }
  // The shim's answer is host code, and the guest will branch straight to it.
  return reinterpret_cast<void*>(
      ShimHandOut(ShimResolve(symbol), symbol));
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

// The visitor is guest code -- this is how the C++ unwinder finds each image's
// .eh_frame -- so it is dispatched, not called.
int DlIteratePhdr(uint64_t callback, void* data) {
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
    const uint64_t args[3] = {reinterpret_cast<uint64_t>(&info),
                              sizeof(info),
                              reinterpret_cast<uint64_t>(data)};
    const int rc = static_cast<int32_t>(
        arc_call_guest(callback, args, 3) & 0xFFFFFFFFu);
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
// No `syslog` here on purpose. It is variadic, and a variadic guest call
// cannot be marshalled by the fixed-arity thunk: its arguments are spread
// across the general registers, the vector registers and the stack by rules
// the thunk has no way to recover. shim_varargs registers it as a
// context-taking native, which can. A second fixed-arity binding for the same
// name resolved only because the varargs layer happens to be asked first, and
// would have marshalled the call wrongly the day that order changed.
void AndroidSetAbortMessage(const char* msg) {
  fprintf(stderr, "abort: %s\n", msg ? msg : "");
}

// Signal delivery has no desktop counterpart worth reproducing: the host
// process is not going to receive SIGPIPE from a loopback socket, and the
// engine's handlers exist for Android's process lifecycle.
// An alternate signal stack exists so a handler can run after the real stack
// overflows. Nothing here delivers signals, so there is nothing to run and
// nowhere for it to run: succeeding is the honest answer, and refusing would
// send the engine down an error path for a facility it never uses.
int Sigaltstack(const void*, void*) { return 0; }
int Setitimer(int, const void*, void*) { return 0; }
int Prctl(int, ...) { return 0; }

// Enough of a filesystem to answer "is there room". Reporting zero free blocks
// would have a title conclude the device is full before it starts.
struct GuestStatfs {
  uint64_t f_type, f_bsize, f_blocks, f_bfree, f_bavail;
  uint64_t f_files, f_ffree;
  uint64_t f_fsid;
  uint64_t f_namelen, f_frsize, f_flags, f_spare[4];
};
int Statfs(const char*, GuestStatfs* out) {
  if (!out) return -1;
  memset(out, 0, sizeof(*out));
  out->f_bsize = 4096;
  out->f_frsize = 4096;
  out->f_blocks = 64ull << 20;  // 256 GB at 4 KB blocks
  out->f_bfree = 32ull << 20;
  out->f_bavail = 32ull << 20;
  out->f_files = 1u << 20;
  out->f_ffree = 1u << 20;
  out->f_namelen = 255;
  return 0;
}

// epoll is how a Linux program waits on descriptors. A desktop port has no use
// for the engine's own event loop -- the window owns that -- so these exist to
// keep the setup path from failing, and a wait times out having seen nothing.
// ponytail: real readiness if a title ever drives its networking through this.
int EpollCreate(int) { return 0x7000001; }
int EpollCreate1(int) { return 0x7000001; }
int EpollCtl(int, int, int, void*) { return 0; }
int EpollWait(int, void*, int, int) { return 0; }
int Eventfd(unsigned, int) { return 0x7000002; }

int Sigaction(int, const void*, void*) { return 0; }
int Sigaddset(void*, int) { return 0; }
int Sigdelset(void*, int) { return 0; }
int Sigemptyset(void*) { return 0; }
int Sigfillset(void*) { return 0; }
int Sigprocmask(int, const void*, void*) { return 0; }
// setjmp and longjmp cannot be forwarded to the host's, for the same reason a
// guest callback cannot be called as a host function: the state they capture
// belongs to the wrong machine. The host's would save host registers and a
// host frame, while the guest expects its own callee-saved registers and stack
// pointer to come back -- and the Microsoft build takes a second, undeclared
// frame argument that our thunk has no way to supply, so it was being handed
// whatever the guest happened to leave in that register.
//
// Nor can a faithful one live here. A host setjmp called inside this function
// would capture *this* frame, which is gone the moment it returns; jumping to
// it later is undefined. Doing it properly means the lifter emitting the
// setjmp inline in the calling function, so the frame it captures is the one
// that will still be there.
//
// The lifter does it properly now: it emits the setjmp inline in the lifted
// function that calls it, so the frame captured is the caller's -- the one
// that has to still be live when the jump lands. These remain only for a call
// made through a function pointer, which no engine seen so far does, and they
// cannot arm anything for the reason above.
//
// This file's earlier answer -- succeed, and report that no jump has happened
// -- was reasoned from the shape of the code rather than measured, on the
// argument that a decoder arms an error handler and then succeeds. It does
// not: Family Guy takes the failure path and calls longjmp for real.
int Setjmp(void*) { return 0; }

[[noreturn]] void Longjmp(void*, int value) {
  char msg[96];
  snprintf(msg, sizeof(msg),
           "the guest called longjmp(%d); no jump target was recorded", value);
  arc_trap(nullptr, msg);
  abort();  // only reached with no recovery point armed
}

[[noreturn]] void Siglongjmp(void* buf, int value) { Longjmp(buf, value); }
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
    E("android_set_abort_message", AndroidSetAbortMessage),

    E("sigaltstack", Sigaltstack),  E("setitimer", Setitimer),
    E("prctl", Prctl),              E("statfs", Statfs),
    E("epoll_create", EpollCreate), E("epoll_create1", EpollCreate1),
    E("epoll_ctl", EpollCtl),       E("epoll_wait", EpollWait),
    E("eventfd", Eventfd),

    E("sigaction", Sigaction),      E("sigaddset", Sigaddset),
    E("sigdelset", Sigdelset),      E("sigemptyset", Sigemptyset),
    E("sigfillset", Sigfillset),    E("sigprocmask", Sigprocmask),
    E("setjmp", Setjmp),           E("longjmp", Longjmp),
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
