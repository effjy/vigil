// vigil — convenience wrappers over the vendored SHA3-512 core.
#ifndef VIGIL_HASH_HPP
#define VIGIL_HASH_HPP

#include "util.hpp"
extern "C" {
#include "sha3.h"
}

namespace vigil {

constexpr size_t kHashLen = SHA3_512_DIGEST_SIZE; // 64

// SHA3-512 of an in-memory buffer.
inline Bytes sha3(const uint8_t* p, size_t n) {
    Bytes d(kHashLen);
    sha3_512(p, n, d.data());
    return d;
}
inline Bytes sha3(const Bytes& b) { return sha3(b.data(), b.size()); }

// SHA3-512 of a file's contents, streamed (constant memory). Throws on error.
Bytes sha3_file(const std::string& path);

} // namespace vigil

#endif
