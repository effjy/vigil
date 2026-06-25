#include "keystore.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

#include <termios.h>
#include <unistd.h>
#include <cstring>

namespace vigil {

namespace {

constexpr uint8_t  KEY_MAGIC[4] = {'V','G','L','K'};
constexpr uint8_t  PUB_MAGIC[4] = {'V','G','L','P'};
constexpr uint16_t KEY_VERSION  = 1;
constexpr size_t   SALT_LEN  = 16;
constexpr size_t   NONCE_LEN = 12;
constexpr size_t   TAG_LEN   = 16;
constexpr size_t   DK_LEN    = 32;   // AES-256 key

// Argon2id work factors. Interactive-ish but not trivial; m_cost in KiB.
constexpr uint32_t A2_T_COST = 3;
constexpr uint32_t A2_M_COST = 1u << 16;  // 64 MiB
constexpr uint32_t A2_PARALLEL = 1;

void derive_key(const std::string& pass, const uint8_t salt[SALT_LEN],
                uint32_t t, uint32_t m, uint32_t p, uint8_t out[DK_LEN]) {
    int rc = argon2id_hash_raw(t, m, p,
                               pass.data(), pass.size(),
                               salt, SALT_LEN,
                               out, DK_LEN);
    if (rc != ARGON2_OK)
        throw Error(std::string("Argon2id failed: ") + argon2_error_message(rc));
}

void random_bytes(uint8_t* p, size_t n) {
    if (RAND_bytes(p, (int)n) != 1) throw Error("RNG failure (RAND_bytes)");
}

// AES-256-GCM. `aad` is authenticated but not encrypted; on decrypt a bad tag
// (wrong passphrase or tampering) makes this throw.
Bytes aes_gcm(bool encrypt, const uint8_t key[DK_LEN], const uint8_t nonce[NONCE_LEN],
              const Bytes& aad, const Bytes& in, uint8_t tag[TAG_LEN]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw Error("EVP_CIPHER_CTX_new failed");
    struct Guard { EVP_CIPHER_CTX* c; ~Guard(){ EVP_CIPHER_CTX_free(c); } } g{ctx};

    const EVP_CIPHER* C = EVP_aes_256_gcm();
    Bytes out(in.size());
    int len = 0, ok;

    if (encrypt) {
        ok = EVP_EncryptInit_ex(ctx, C, nullptr, key, nonce);
        if (ok) ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());
        if (ok) ok = EVP_EncryptUpdate(ctx, out.data(), &len, in.data(), (int)in.size());
        int total = len;
        if (ok) ok = EVP_EncryptFinal_ex(ctx, out.data()+total, &len);
        total += len;
        if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
        if (!ok) throw Error("AES-GCM encryption failed");
        out.resize(total);
    } else {
        ok = EVP_DecryptInit_ex(ctx, C, nullptr, key, nonce);
        if (ok) ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());
        if (ok) ok = EVP_DecryptUpdate(ctx, out.data(), &len, in.data(), (int)in.size());
        int total = len;
        if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
        if (ok) ok = EVP_DecryptFinal_ex(ctx, out.data()+total, &len);
        if (!ok) throw Error("decryption failed: wrong passphrase or corrupt/tampered key file");
        total += len;
        out.resize(total);
    }
    return out;
}

} // namespace

void keystore_generate(const std::string& alg, const std::string& keypath,
                       const std::string& pubpath, const std::string& passphrase) {
    KeyPair kp = sig_keypair(alg);

    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], dk[DK_LEN], tag[TAG_LEN];
    random_bytes(salt, SALT_LEN);
    random_bytes(nonce, NONCE_LEN);
    derive_key(passphrase, salt, A2_T_COST, A2_M_COST, A2_PARALLEL, dk);

    // Build the authenticated header (everything that is not the ciphertext).
    Bytes hdr;
    put_bytes(hdr, KEY_MAGIC, 4);
    put_u16(hdr, KEY_VERSION);
    put_str(hdr, kp.alg);
    put_bytes(hdr, salt, SALT_LEN);
    put_u32(hdr, A2_T_COST);
    put_u32(hdr, A2_M_COST);
    put_u32(hdr, A2_PARALLEL);
    put_bytes(hdr, nonce, NONCE_LEN);

    Bytes ct = aes_gcm(true, dk, nonce, hdr, kp.secret, tag);
    secure_wipe(dk, sizeof dk);

    Bytes file = hdr;
    put_blob(file, ct);
    put_bytes(file, tag, TAG_LEN);
    put_blob(file, kp.pub);
    write_file_atomic(keypath, file, 0600);

    Bytes pub;
    put_bytes(pub, PUB_MAGIC, 4);
    put_u16(pub, KEY_VERSION);
    put_str(pub, kp.alg);
    put_blob(pub, kp.pub);
    write_file_atomic(pubpath, pub, 0644);
}

KeyPair keystore_load_secret(const std::string& keypath, const std::string& passphrase) {
    Bytes file = read_file(keypath);
    Reader r(file);

    uint8_t magic[4]; r.bytes(magic, 4);
    if (std::memcmp(magic, KEY_MAGIC, 4) != 0) throw Error("'" + keypath + "' is not a vigil key file");
    uint16_t ver = r.u16();
    if (ver != KEY_VERSION) throw Error("unsupported key file version");
    std::string alg = r.str();
    uint8_t salt[SALT_LEN]; r.bytes(salt, SALT_LEN);
    uint32_t t = r.u32(), m = r.u32(), p = r.u32();
    uint8_t nonce[NONCE_LEN]; r.bytes(nonce, NONCE_LEN);

    // The authenticated header is exactly the bytes consumed so far.
    Bytes hdr(file.begin(), file.begin() + r.offset());

    Bytes ct = r.blob();
    uint8_t tag[TAG_LEN]; r.bytes(tag, TAG_LEN);
    Bytes pub = r.blob();

    uint8_t dk[DK_LEN];
    derive_key(passphrase, salt, t, m, p, dk);
    Bytes secret = aes_gcm(false, dk, nonce, hdr, ct, tag);
    secure_wipe(dk, sizeof dk);

    KeyPair kp;
    kp.alg = alg;
    kp.pub = std::move(pub);
    kp.secret = std::move(secret);
    return kp;
}

PublicKey keystore_load_public(const std::string& pubpath) {
    Bytes file = read_file(pubpath);
    Reader r(file);
    uint8_t magic[4]; r.bytes(magic, 4);
    if (std::memcmp(magic, PUB_MAGIC, 4) != 0) throw Error("'" + pubpath + "' is not a vigil public-key file");
    uint16_t ver = r.u16();
    if (ver != KEY_VERSION) throw Error("unsupported public-key file version");
    PublicKey pk;
    pk.alg = r.str();
    pk.pub = r.blob();
    return pk;
}

std::string prompt_passphrase(const std::string& prompt, bool confirm) {
    if (!isatty(STDIN_FILENO))
        throw Error("a passphrase is required but stdin is not a terminal "
                    "(set VIGIL_PASSPHRASE to script this)");

    auto read_once = [](const std::string& p) -> std::string {
        std::fputs(p.c_str(), stderr);
        std::fflush(stderr);
        termios oldt{}; tcgetattr(STDIN_FILENO, &oldt);
        termios noecho = oldt; noecho.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);
        std::string line;
        int c;
        while ((c = std::getchar()) != EOF && c != '\n') line.push_back((char)c);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        std::fputc('\n', stderr);
        return line;
    };

    std::string pass = read_once(prompt);
    if (confirm) {
        std::string again = read_once("Confirm passphrase: ");
        if (pass != again) {
            secure_wipe(pass.data(), pass.size());
            secure_wipe(again.data(), again.size());
            throw Error("passphrases did not match");
        }
        secure_wipe(again.data(), again.size());
    }
    if (pass.empty()) throw Error("empty passphrase refused");
    return pass;
}

} // namespace vigil
