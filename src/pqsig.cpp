#include "pqsig.hpp"

#include <oqs/oqs.h>
#include <memory>
#include <cctype>
#include <utility>

namespace vigil {

namespace {
// RAII wrapper so an OQS_SIG handle is always freed, even on throw.
struct SigHandle {
    OQS_SIG* s = nullptr;
    explicit SigHandle(const std::string& alg) {
        s = OQS_SIG_new(alg.c_str());
        if (!s) throw Error("liboqs does not support signature algorithm '" + alg + "'");
    }
    ~SigHandle() { if (s) OQS_SIG_free(s); }
    OQS_SIG* operator->() const { return s; }
};
} // namespace

std::string sig_canonical_alg(const std::string& name) {
    // Accept a few spellings; liboqs itself wants the canonical "ML-DSA-65".
    static const std::pair<const char*, const char*> table[] = {
        {"ml-dsa-44", OQS_SIG_alg_ml_dsa_44},
        {"ml-dsa-65", OQS_SIG_alg_ml_dsa_65},
        {"ml-dsa-87", OQS_SIG_alg_ml_dsa_87},
    };
    std::string lower;
    for (char c : name) lower.push_back((char)std::tolower((unsigned char)c));
    for (auto& [k, v] : table)
        if (lower == k) {
            if (!OQS_SIG_alg_is_enabled(v))
                throw Error(std::string("signature algorithm not enabled in liboqs: ") + v);
            return v;
        }
    // Maybe the caller already passed a canonical liboqs name.
    if (OQS_SIG_alg_is_enabled(name.c_str())) return name;
    throw Error("unknown signature algorithm: '" + name + "'");
}

KeyPair sig_keypair(const std::string& alg) {
    std::string canon = sig_canonical_alg(alg);
    SigHandle sig(canon);
    KeyPair kp;
    kp.alg = canon;
    kp.pub.resize(sig->length_public_key);
    kp.secret.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig.s, kp.pub.data(), kp.secret.data()) != OQS_SUCCESS)
        throw Error("ML-DSA key generation failed");
    return kp;
}

Bytes sig_sign(const std::string& alg, const Bytes& secret, const Bytes& msg) {
    std::string canon = sig_canonical_alg(alg);
    SigHandle sig(canon);
    if (secret.size() != sig->length_secret_key)
        throw Error("secret key size mismatch for " + canon);
    Bytes out(sig->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_sign(sig.s, out.data(), &siglen, msg.data(), msg.size(),
                     secret.data()) != OQS_SUCCESS)
        throw Error("ML-DSA signing failed");
    out.resize(siglen);
    return out;
}

bool sig_verify(const std::string& alg, const Bytes& pub,
                const Bytes& msg, const Bytes& signature) {
    std::string canon = sig_canonical_alg(alg);
    SigHandle sig(canon);
    if (pub.size() != sig->length_public_key)
        throw Error("public key size mismatch for " + canon);
    return OQS_SIG_verify(sig.s, msg.data(), msg.size(),
                          signature.data(), signature.size(),
                          pub.data()) == OQS_SUCCESS;
}

} // namespace vigil
