// zlib, across an ABI boundary that looks like it is not there.
//
// Every zlib function the engine imports has an identical signature on both
// sides, so the shim bound them straight through -- and that was wrong for the
// half that take a `z_stream*`. `uLong` is `unsigned long`, which is 8 bytes on
// Android arm64 and 4 on Windows, so the same struct is 112 bytes in the guest
// and 88 here, with `next_out` and everything after it at different offsets.
//
// The symptom was not a crash. `inflateInit2_` compares the caller's
// `stream_size` against its own and answers Z_VERSION_ERROR; the engine does
// not check, calls `inflate` on an uninitialised stream, gets Z_STREAM_ERROR,
// and carries an empty buffer away. Every asset in a pack decompressed to
// nothing, which meant every image was zero pixels wide, which meant a black
// window behind a full frame of draw calls.
//
// So the guest's struct is read and written by offset, and a host `z_stream`
// lives beside it. The guest's own `state` field is where the host stream is
// kept: it is opaque to the caller by contract, which is exactly the property
// needed.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "shim.h"

#if defined(ARC_HAVE_ZLIB)
#include <zlib.h>

namespace arc {
namespace {

// The Android arm64 layout, by offset. Writing it as a struct would leave the
// padding to this compiler, which is the thing that differs.
constexpr size_t kNextIn = 0;
constexpr size_t kAvailIn = 8;
constexpr size_t kTotalIn = 16;
constexpr size_t kNextOut = 24;
constexpr size_t kAvailOut = 32;
constexpr size_t kTotalOut = 40;
constexpr size_t kMsg = 48;
constexpr size_t kState = 56;
constexpr size_t kZalloc = 64;
constexpr size_t kDataType = 88;
constexpr size_t kAdler = 96;

uint64_t Get64(void* p, size_t off) {
  uint64_t v;
  memcpy(&v, static_cast<char*>(p) + off, sizeof v);
  return v;
}
uint32_t Get32(void* p, size_t off) {
  uint32_t v;
  memcpy(&v, static_cast<char*>(p) + off, sizeof v);
  return v;
}
void Put64(void* p, size_t off, uint64_t v) {
  memcpy(static_cast<char*>(p) + off, &v, sizeof v);
}
void Put32(void* p, size_t off, uint32_t v) {
  memcpy(static_cast<char*>(p) + off, &v, sizeof v);
}

z_stream* HostOf(void* guest) {
  return guest ? reinterpret_cast<z_stream*>(Get64(guest, kState)) : nullptr;
}

// Only the four the caller sets before each call. The rest are ours to report.
void PushIn(void* guest, z_stream* host) {
  host->next_in = reinterpret_cast<Bytef*>(Get64(guest, kNextIn));
  host->avail_in = Get32(guest, kAvailIn);
  host->next_out = reinterpret_cast<Bytef*>(Get64(guest, kNextOut));
  host->avail_out = Get32(guest, kAvailOut);
}

void PullOut(void* guest, z_stream* host) {
  Put64(guest, kNextIn, reinterpret_cast<uint64_t>(host->next_in));
  Put32(guest, kAvailIn, host->avail_in);
  Put64(guest, kTotalIn, host->total_in);
  Put64(guest, kNextOut, reinterpret_cast<uint64_t>(host->next_out));
  Put32(guest, kAvailOut, host->avail_out);
  Put64(guest, kTotalOut, host->total_out);
  Put64(guest, kMsg, reinterpret_cast<uint64_t>(host->msg));
  Put32(guest, kDataType, static_cast<uint32_t>(host->data_type));
  Put64(guest, kAdler, host->adler);
}

// A host stream attached to a guest one, zeroed. The guest's allocator hooks
// are deliberately not carried over: they are arm64 code, and calling them
// would need a guest context this side of the boundary has no access to.
// zlib's own malloc is the substitute, which changes where the window lives
// and nothing else.
z_stream* Attach(void* guest) {
  if (!guest) return nullptr;
  if (Get64(guest, kZalloc)) {
    static bool said = false;
    if (!said) {
      said = true;
      fprintf(stderr,
              "[zlib] the engine set its own allocator; using zlib's\n");
    }
  }
  auto* host = static_cast<z_stream*>(calloc(1, sizeof(z_stream)));
  Put64(guest, kState, reinterpret_cast<uint64_t>(host));
  return host;
}

void Detach(void* guest, z_stream* host) {
  free(host);
  if (guest) Put64(guest, kState, 0);
}

int Report(const char* what, int rc) {
  static const bool trace = getenv("ARC_TRACE_ZLIB") != nullptr;
  if (rc < 0 || trace) fprintf(stderr, "[zlib] %s -> %d\n", what, rc);
  return rc;
}

int InflateInit2(void* guest, int window_bits, const char*, int) {
  z_stream* host = Attach(guest);
  if (!host) return Z_MEM_ERROR;
  // Our own version and size, not the guest's: the guest's describe a struct
  // this zlib has never seen.
  const int rc = inflateInit2_(host, window_bits, ZLIB_VERSION,
                               static_cast<int>(sizeof(z_stream)));
  PullOut(guest, host);
  return Report("inflateInit2", rc);
}

int InflateInit(void* guest, const char* version, int stream_size) {
  return InflateInit2(guest, MAX_WBITS, version, stream_size);
}

int Inflate(void* guest, int flush) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  PushIn(guest, host);
  const int rc = inflate(host, flush);
  PullOut(guest, host);
  return rc < 0 ? Report("inflate", rc) : rc;
}

int InflateEnd(void* guest) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  const int rc = inflateEnd(host);
  Detach(guest, host);
  return rc;
}

int InflateReset(void* guest) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  const int rc = inflateReset(host);
  PullOut(guest, host);
  return rc;
}

int DeflateInit2(void* guest, int level, int method, int window_bits,
                 int mem_level, int strategy, const char*, int) {
  z_stream* host = Attach(guest);
  if (!host) return Z_MEM_ERROR;
  const int rc =
      deflateInit2_(host, level, method, window_bits, mem_level, strategy,
                    ZLIB_VERSION, static_cast<int>(sizeof(z_stream)));
  PullOut(guest, host);
  return Report("deflateInit2", rc);
}

int DeflateInit(void* guest, int level, const char*, int) {
  return DeflateInit2(guest, level, Z_DEFLATED, MAX_WBITS, 8,
                      Z_DEFAULT_STRATEGY, nullptr, 0);
}

int Deflate(void* guest, int flush) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  PushIn(guest, host);
  const int rc = deflate(host, flush);
  PullOut(guest, host);
  return rc < 0 ? Report("deflate", rc) : rc;
}

int DeflateEnd(void* guest) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  const int rc = deflateEnd(host);
  Detach(guest, host);
  return rc;
}

int DeflateReset(void* guest) {
  z_stream* host = HostOf(guest);
  if (!host) return Z_STREAM_ERROR;
  const int rc = deflateReset(host);
  PullOut(guest, host);
  return rc;
}

struct Entry {
  const char* name;
  void* fn;
};
#define E(n, f) {n, reinterpret_cast<void*>(&f)}
const Entry kTable[] = {
    E("inflateInit_", InflateInit),   E("inflateInit2_", InflateInit2),
    E("inflate", Inflate),            E("inflateEnd", InflateEnd),
    E("inflateReset", InflateReset),  E("deflateInit_", DeflateInit),
    E("deflateInit2_", DeflateInit2), E("deflate", Deflate),
    E("deflateEnd", DeflateEnd),      E("deflateReset", DeflateReset),
};
#undef E

}  // namespace

uint64_t ShimResolveZlib(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

}  // namespace arc

#else

namespace arc {
uint64_t ShimResolveZlib(const char*) { return 0; }
}  // namespace arc

#endif
