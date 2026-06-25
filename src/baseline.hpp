// vigil — the signed baseline database (".vgl").
//
// Layout (all little-endian):
//
//   --- signed body ---
//   magic "VGL1" | version u16 | alg str | root str | created u64
//   prev_root[64]            (zero unless this baseline chains to an older one)
//   n_excludes u32 | exclude str * n_excludes   (patterns applied at scan time)
//   n_records u64
//   { path str | type u8 | mode u32 | uid u32 | gid u32 | size u64
//     | mtime i64 | hash blob } * n_records      (records sorted by path)
//   merkle_root[64]          (Merkle tree over per-record leaf hashes)
//   --- trailer (not part of the signed digest) ---
//   pub blob                 (signer's public key, informational)
//   sig blob                 (ML-DSA over SHA3-512(signed body))
//
// Trust comes from the verifier's own vigil.pub, never the embedded copy.
#ifndef VIGIL_BASELINE_HPP
#define VIGIL_BASELINE_HPP

#include "scan.hpp"
#include "keystore.hpp"
#include "hash.hpp"
#include <string>
#include <vector>

namespace vigil {

struct Baseline {
    std::string         alg = kDefaultSigAlg;
    std::string         root;
    uint64_t            created = 0;
    Bytes               prev_root;          // kHashLen, all-zero if none
    std::vector<std::string> excludes;      // exclude patterns applied at scan
    std::vector<Record> records;
    Bytes               merkle_root;        // kHashLen
    Bytes               pub;                // embedded signer public key
    Bytes               signature;          // empty until signed

    Bytes               signed_body;        // exact bytes that were/are signed
};

// Build an unsigned baseline from a scan. `prev_root` may be empty.
Baseline baseline_build(const ScanResult& scan, const std::string& alg,
                        const Bytes& prev_root);

// Serialize the signed body into `b.signed_body` and compute `b.merkle_root`.
void baseline_finalize_body(Baseline& b);

// Sign the finalized body and attach signature + public key.
void baseline_sign(Baseline& b, const KeyPair& key);

// Write / read the full ".vgl" file.
void     baseline_save(const std::string& path, const Baseline& b);
Baseline baseline_load(const std::string& path);

// Verify the embedded signature against a trusted public key.
bool baseline_verify(const Baseline& b, const PublicKey& pk);

// Merkle root over the records (domain-separated leaf/node hashing).
Bytes merkle_root(const std::vector<Record>& records);

// ---- diff -----------------------------------------------------------------
struct Change {
    enum class Kind { Added, Removed, Modified } kind;
    std::string path;
    std::string detail;   // for Modified: which attributes changed
};

// Compare an old record set to a new one (both sorted by path).
std::vector<Change> baseline_diff(const std::vector<Record>& oldr,
                                  const std::vector<Record>& newr);

// "added" | "removed" | "modified"
const char* change_kind_name(Change::Kind k);

// Compare two records for the same path; returns a comma-joined list of the
// attributes that differ ("type", "content", "mode", …) or "" if identical.
std::string record_compare(const Record& a, const Record& b);

} // namespace vigil

#endif
