#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA3_512_DIGEST_SIZE  64
#define SHA3_512_RATE         72   /* (1600 - 2*512) / 8 */

typedef struct {
    uint64_t state[25];
    uint8_t  buf[SHA3_512_RATE];
    size_t   buf_len;
} sha3_512_ctx;

void sha3_512_init(sha3_512_ctx *ctx);
void sha3_512_update(sha3_512_ctx *ctx, const uint8_t *data, size_t len);
void sha3_512_final(sha3_512_ctx *ctx, uint8_t digest[SHA3_512_DIGEST_SIZE]);
void sha3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]);

/* Hash a file by path; returns 0 on success, -1 on error */
int sha3_512_file(const char *path, uint8_t digest[SHA3_512_DIGEST_SIZE]);

/* Convert digest to lowercase hex string (128 chars + NUL) */
void sha3_512_hex(const uint8_t digest[SHA3_512_DIGEST_SIZE], char hex[SHA3_512_DIGEST_SIZE * 2 + 1]);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_H */
