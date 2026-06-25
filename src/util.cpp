#include "util.hpp"

#include <cstring>
#include <cstdio>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace vigil {

// ---- writers --------------------------------------------------------------
void put_u8 (Bytes& b, uint8_t v) { b.push_back(v); }
void put_u16(Bytes& b, uint16_t v){ for (int i=0;i<2;i++) b.push_back(uint8_t(v>>(8*i))); }
void put_u32(Bytes& b, uint32_t v){ for (int i=0;i<4;i++) b.push_back(uint8_t(v>>(8*i))); }
void put_u64(Bytes& b, uint64_t v){ for (int i=0;i<8;i++) b.push_back(uint8_t(v>>(8*i))); }
void put_i64(Bytes& b, int64_t v) { put_u64(b, (uint64_t)v); }

void put_bytes(Bytes& b, const void* p, size_t n) {
    const auto* c = static_cast<const uint8_t*>(p);
    b.insert(b.end(), c, c + n);
}
void put_str(Bytes& b, const std::string& s) {
    if (s.size() > 0xFFFF) throw Error("string too long to serialize");
    put_u16(b, (uint16_t)s.size());
    put_bytes(b, s.data(), s.size());
}
void put_blob(Bytes& b, const Bytes& v) {
    if (v.size() > 0xFFFFFFFFu) throw Error("blob too long to serialize");
    put_u32(b, (uint32_t)v.size());
    put_bytes(b, v.data(), v.size());
}

// ---- reader ---------------------------------------------------------------
void Reader::need(size_t n) const {
    if (off_ + n > n_) throw Error("malformed/truncated data");
}
uint8_t Reader::u8() { need(1); return p_[off_++]; }
uint16_t Reader::u16(){ need(2); uint16_t v=0; for(int i=0;i<2;i++) v|=uint16_t(p_[off_++])<<(8*i); return v; }
uint32_t Reader::u32(){ need(4); uint32_t v=0; for(int i=0;i<4;i++) v|=uint32_t(p_[off_++])<<(8*i); return v; }
uint64_t Reader::u64(){ need(8); uint64_t v=0; for(int i=0;i<8;i++) v|=uint64_t(p_[off_++])<<(8*i); return v; }
int64_t  Reader::i64(){ return (int64_t)u64(); }
void Reader::bytes(void* dst, size_t n){ need(n); std::memcpy(dst, p_+off_, n); off_+=n; }
std::string Reader::str(){ uint16_t n=u16(); need(n); std::string s((const char*)p_+off_, n); off_+=n; return s; }
Bytes Reader::blob(){ uint32_t n=u32(); need(n); Bytes v(p_+off_, p_+off_+n); off_+=n; return v; }

// ---- hex ------------------------------------------------------------------
std::string to_hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n*2);
    for (size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xF]); }
    return s;
}
Bytes from_hex(const std::string& hex) {
    if (hex.size() % 2) throw Error("hex string has odd length");
    auto nib = [](char c)->int{
        if (c>='0'&&c<='9') return c-'0';
        if (c>='a'&&c<='f') return c-'a'+10;
        if (c>='A'&&c<='F') return c-'A'+10;
        throw Error("invalid hex digit");
    };
    Bytes out; out.reserve(hex.size()/2);
    for (size_t i=0;i<hex.size();i+=2) out.push_back(uint8_t(nib(hex[i])<<4 | nib(hex[i+1])));
    return out;
}

// ---- json -----------------------------------------------------------------
std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    static const char* H = "0123456789abcdef";
                    o += "\\u00"; o += H[c>>4]; o += H[c&0xF];
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

// ---- secure wipe ----------------------------------------------------------
void secure_wipe(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

// ---- file I/O -------------------------------------------------------------
Bytes read_file(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) throw Error("cannot open '" + path + "': " + std::strerror(errno));
    Bytes out;
    uint8_t buf[65536];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf+r);
    bool err = std::ferror(f);
    std::fclose(f);
    if (err) throw Error("read error on '" + path + "'");
    return out;
}

void write_file_atomic(const std::string& path, const Bytes& data, unsigned mode) {
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY|O_CREAT|O_TRUNC, mode);
    if (fd < 0) throw Error("cannot create '" + tmp + "': " + std::strerror(errno));
    size_t off = 0;
    while (off < data.size()) {
        ssize_t w = ::write(fd, data.data()+off, data.size()-off);
        if (w < 0) { ::close(fd); ::unlink(tmp.c_str()); throw Error("write failed on '" + tmp + "'"); }
        off += (size_t)w;
    }
    ::fchmod(fd, mode);
    if (::fsync(fd) != 0) { ::close(fd); ::unlink(tmp.c_str()); throw Error("fsync failed"); }
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw Error("rename into place failed for '" + path + "'");
    }
}

} // namespace vigil
