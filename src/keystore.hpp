// vigil — key files.
//
//   vigil.key  (VGLK)  secret key, encrypted at rest with AES-256-GCM under
//                      a key derived from a passphrase via Argon2id.
//   vigil.pub  (VGLP)  public key, stored in the clear.
//
// The signer never writes a raw secret key to disk.
#ifndef VIGIL_KEYSTORE_HPP
#define VIGIL_KEYSTORE_HPP

#include "pqsig.hpp"
#include <string>

namespace vigil {

struct PublicKey {
    std::string alg;
    Bytes       pub;
};

// Generate a keypair and write both files. `keypath` is created 0600.
void keystore_generate(const std::string& alg,
                       const std::string& keypath,
                       const std::string& pubpath,
                       const std::string& passphrase);

// Decrypt and return the secret key (+ its public half and alg).
KeyPair keystore_load_secret(const std::string& keypath,
                             const std::string& passphrase);

// Read a public-key file.
PublicKey keystore_load_public(const std::string& pubpath);

// Prompt on the controlling terminal with echo disabled. `confirm` asks twice
// and requires a match. Throws if there is no TTY.
std::string prompt_passphrase(const std::string& prompt, bool confirm);

} // namespace vigil

#endif
