// vigil — post-quantum signatures (ML-DSA / FIPS 204) via liboqs.
//
// We sign the 64-byte SHA3-512 digest of the serialized baseline, not the
// baseline itself, so signing cost is independent of how large the tree is.
#ifndef VIGIL_PQSIG_HPP
#define VIGIL_PQSIG_HPP

#include "util.hpp"
#include <string>

namespace vigil {

// Default parameter set. ML-DSA-65 ~ NIST security category 3, the same
// middle-of-the-road choice pq-sign/pq-audit default to.
constexpr const char* kDefaultSigAlg = "ML-DSA-65";

// Map a friendly/loose name ("ml-dsa-65", "ML-DSA-65") to the exact liboqs
// method name, or throw if the build of liboqs does not enable it.
std::string sig_canonical_alg(const std::string& name);

struct KeyPair {
    std::string alg;
    Bytes       secret;   // raw liboqs secret key
    Bytes       pub;      // raw liboqs public key
    ~KeyPair() { if (!secret.empty()) secure_wipe(secret.data(), secret.size()); }
};

// Generate a fresh ML-DSA keypair for `alg`.
KeyPair sig_keypair(const std::string& alg);

// Sign / verify a message (we pass the SHA3-512 digest as the message).
Bytes sig_sign(const std::string& alg, const Bytes& secret, const Bytes& msg);
bool  sig_verify(const std::string& alg, const Bytes& pub,
                 const Bytes& msg, const Bytes& signature);

} // namespace vigil

#endif
