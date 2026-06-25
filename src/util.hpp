// vigil — small shared helpers (no crypto, no I/O policy)
#ifndef VIGIL_UTIL_HPP
#define VIGIL_UTIL_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>

namespace vigil {

using Bytes = std::vector<uint8_t>;

// A plain runtime error we throw for any recoverable failure; main() turns
// these into a clean "vigil: <msg>" line and a non-zero exit.
struct Error : std::runtime_error {
    explicit Error(const std::string& m) : std::runtime_error(m) {}
};

// ---- little-endian integer (de)serialization into a growing buffer --------
void put_u8 (Bytes& b, uint8_t  v);
void put_u16(Bytes& b, uint16_t v);
void put_u32(Bytes& b, uint32_t v);
void put_u64(Bytes& b, uint64_t v);
void put_i64(Bytes& b, int64_t  v);
void put_bytes(Bytes& b, const void* p, size_t n);
// length-prefixed string (u16 length) / blob (u32 length)
void put_str(Bytes& b, const std::string& s);
void put_blob(Bytes& b, const Bytes& v);

// A cursor over an immutable byte span; every read is bounds-checked and
// throws vigil::Error on truncation, so parsers stay short and safe.
class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n), off_(0) {}
    explicit Reader(const Bytes& b) : Reader(b.data(), b.size()) {}

    uint8_t  u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    int64_t  i64();
    void     bytes(void* dst, size_t n);
    std::string str();      // u16-prefixed
    Bytes       blob();     // u32-prefixed
    size_t   remaining() const { return n_ - off_; }
    size_t   offset()    const { return off_; }

private:
    void need(size_t n) const;
    const uint8_t* p_;
    size_t n_, off_;
};

// ---- misc -----------------------------------------------------------------
std::string to_hex(const uint8_t* p, size_t n);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
Bytes from_hex(const std::string& hex);

// Best-effort wipe that the optimizer is not allowed to elide.
void secure_wipe(void* p, size_t n);

// Escape a string for embedding in a JSON document (no surrounding quotes).
std::string json_escape(const std::string& s);

// Whole-file read/atomic-write. write_file_atomic writes to <path>.tmp then
// rename()s, and chmods to `mode`; load throws if the file is missing.
Bytes read_file(const std::string& path);
void  write_file_atomic(const std::string& path, const Bytes& data, unsigned mode);

} // namespace vigil

#endif
