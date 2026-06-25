#include "baseline.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace vigil {

namespace {

constexpr uint8_t  DB_MAGIC[4] = {'V','G','L','1'};
constexpr uint16_t DB_VERSION  = 2;   // v2 adds the exclude-pattern list

void put_record(Bytes& b, const Record& r) {
    put_str(b, r.path);
    put_u8 (b, (uint8_t)r.type);
    put_u32(b, r.mode);
    put_u32(b, r.uid);
    put_u32(b, r.gid);
    put_u64(b, r.size);
    put_i64(b, r.mtime);
    put_blob(b, r.hash);
}

Record get_record(Reader& r) {
    Record rec;
    rec.path  = r.str();
    rec.type  = (EntryType)r.u8();
    rec.mode  = r.u32();
    rec.uid   = r.u32();
    rec.gid   = r.u32();
    rec.size  = r.u64();
    rec.mtime = r.i64();
    rec.hash  = r.blob();
    return rec;
}

// Canonical per-record bytes used as a Merkle leaf preimage.
Bytes record_bytes(const Record& r) { Bytes b; put_record(b, r); return b; }

Bytes hash_leaf(const Bytes& rec) {
    Bytes pre; pre.push_back(0x00);
    pre.insert(pre.end(), rec.begin(), rec.end());
    return sha3(pre);
}
Bytes hash_node(const Bytes& l, const Bytes& r) {
    Bytes pre; pre.push_back(0x01);
    pre.insert(pre.end(), l.begin(), l.end());
    pre.insert(pre.end(), r.begin(), r.end());
    return sha3(pre);
}

} // namespace

Bytes merkle_root(const std::vector<Record>& records) {
    if (records.empty()) return Bytes(kHashLen, 0);  // empty tree => zero root
    std::vector<Bytes> level;
    level.reserve(records.size());
    for (const auto& r : records) level.push_back(hash_leaf(record_bytes(r)));
    while (level.size() > 1) {
        std::vector<Bytes> next;
        next.reserve((level.size()+1)/2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const Bytes& l = level[i];
            const Bytes& r = (i+1 < level.size()) ? level[i+1] : level[i]; // dup last if odd
            next.push_back(hash_node(l, r));
        }
        level.swap(next);
    }
    return level[0];
}

Baseline baseline_build(const ScanResult& scan, const std::string& alg, const Bytes& prev_root) {
    Baseline b;
    b.alg     = sig_canonical_alg(alg);
    b.root    = scan.root;
    b.created = (uint64_t)std::time(nullptr);
    b.prev_root = prev_root.empty() ? Bytes(kHashLen, 0) : prev_root;
    if (b.prev_root.size() != kHashLen) throw Error("prev_root has wrong length");
    b.excludes = scan.excludes;
    b.records = scan.records;
    return b;
}

void baseline_finalize_body(Baseline& b) {
    b.merkle_root = merkle_root(b.records);
    if (b.prev_root.size() != kHashLen) b.prev_root.assign(kHashLen, 0);

    Bytes body;
    put_bytes(body, DB_MAGIC, 4);
    put_u16(body, DB_VERSION);
    put_str(body, b.alg);
    put_str(body, b.root);
    put_u64(body, b.created);
    put_bytes(body, b.prev_root.data(), kHashLen);
    if (b.excludes.size() > 0xFFFFFFFFu) throw Error("too many exclude patterns");
    put_u32(body, (uint32_t)b.excludes.size());
    for (const auto& e : b.excludes) put_str(body, e);
    put_u64(body, (uint64_t)b.records.size());
    for (const auto& r : b.records) put_record(body, r);
    put_bytes(body, b.merkle_root.data(), kHashLen);
    b.signed_body = std::move(body);
}

void baseline_sign(Baseline& b, const KeyPair& key) {
    if (b.signed_body.empty()) baseline_finalize_body(b);
    Bytes digest = sha3(b.signed_body);
    b.signature = sig_sign(key.alg, key.secret, digest);
    b.pub = key.pub;
    b.alg = key.alg;
}

void baseline_save(const std::string& path, const Baseline& b) {
    if (b.signed_body.empty() || b.signature.empty())
        throw Error("internal: baseline must be signed before saving");
    Bytes file = b.signed_body;
    put_blob(file, b.pub);
    put_blob(file, b.signature);
    write_file_atomic(path, file, 0644);
}

Baseline baseline_load(const std::string& path) {
    Bytes file = read_file(path);
    Reader r(file);

    uint8_t magic[4]; r.bytes(magic, 4);
    if (std::memcmp(magic, DB_MAGIC, 4) != 0) throw Error("'" + path + "' is not a vigil baseline");
    uint16_t ver = r.u16();
    if (ver != DB_VERSION) throw Error("unsupported baseline version");

    Baseline b;
    b.alg     = r.str();
    b.root    = r.str();
    b.created = r.u64();
    b.prev_root.resize(kHashLen); r.bytes(b.prev_root.data(), kHashLen);
    uint32_t nex = r.u32();
    b.excludes.reserve(nex);
    for (uint32_t i = 0; i < nex; ++i) b.excludes.push_back(r.str());
    uint64_t n = r.u64();
    b.records.reserve(n);
    for (uint64_t i = 0; i < n; ++i) b.records.push_back(get_record(r));
    b.merkle_root.resize(kHashLen); r.bytes(b.merkle_root.data(), kHashLen);

    // The signed body is everything consumed up to this point.
    b.signed_body.assign(file.begin(), file.begin() + r.offset());

    b.pub       = r.blob();
    b.signature = r.blob();

    // Re-derive the merkle root and make sure the body is internally consistent.
    if (merkle_root(b.records) != b.merkle_root)
        throw Error("baseline is corrupt: Merkle root does not match records");
    return b;
}

bool baseline_verify(const Baseline& b, const PublicKey& pk) {
    // A key for a different algorithm (or of the wrong size) cannot have
    // produced this signature, so it is simply invalid — not a usage error.
    if (pk.alg != b.alg) return false;
    Bytes digest = sha3(b.signed_body);
    return sig_verify(b.alg, pk.pub, digest, b.signature);
}

const char* change_kind_name(Change::Kind k) {
    switch (k) {
        case Change::Kind::Added:    return "added";
        case Change::Kind::Removed:  return "removed";
        default:                     return "modified";
    }
}

// ---- diff -----------------------------------------------------------------
std::string record_compare(const Record& a, const Record& b) {
    std::string d;
    auto add = [&](const char* w){ if (!d.empty()) d += ","; d += w; };
    if (a.type != b.type) add("type");
    if (a.hash != b.hash) add("content");
    if ((a.mode & 07777) != (b.mode & 07777)) add("mode");
    if (a.uid != b.uid)   add("uid");
    if (a.gid != b.gid)   add("gid");
    if (a.size != b.size) add("size");
    if (a.mtime != b.mtime) add("mtime");
    return d;
}

std::vector<Change> baseline_diff(const std::vector<Record>& oldr,
                                  const std::vector<Record>& newr) {
    std::vector<Change> out;
    size_t i = 0, j = 0;
    while (i < oldr.size() || j < newr.size()) {
        if (j >= newr.size() || (i < oldr.size() && oldr[i].path < newr[j].path)) {
            out.push_back({Change::Kind::Removed, oldr[i].path, ""});
            ++i;
        } else if (i >= oldr.size() || newr[j].path < oldr[i].path) {
            out.push_back({Change::Kind::Added, newr[j].path, ""});
            ++j;
        } else {
            std::string d = record_compare(oldr[i], newr[j]);
            if (!d.empty()) out.push_back({Change::Kind::Modified, newr[j].path, d});
            ++i; ++j;
        }
    }
    return out;
}

} // namespace vigil
