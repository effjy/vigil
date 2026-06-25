#include "hash.hpp"
#include <cstdio>
#include <cstring>
#include <cerrno>

namespace vigil {

Bytes sha3_file(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) throw Error("cannot hash '" + path + "': " + std::strerror(errno));
    sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    uint8_t buf[65536];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof buf, f)) > 0)
        sha3_512_update(&ctx, buf, r);
    bool err = std::ferror(f);
    std::fclose(f);
    if (err) throw Error("read error while hashing '" + path + "'");
    Bytes d(kHashLen);
    sha3_512_final(&ctx, d.data());
    return d;
}

} // namespace vigil
