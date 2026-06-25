#include "sha3.h"
#include <string.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * Keccak-f[1600] round constants and rotation offsets
 * -------------------------------------------------------------------------- */

static const uint64_t RC[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

static const int ROT[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14},
};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/* --------------------------------------------------------------------------
 * Keccak-f[1600] permutation
 * -------------------------------------------------------------------------- */

static void keccakf(uint64_t A[25])
{
    uint64_t C[5], D[5], B[5][5];
    int r, x, y;

    for (r = 0; r < 24; r++) {
        /* Theta */
        for (x = 0; x < 5; x++)
            C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
        for (x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                A[y*5+x] ^= D[x];

        /* Rho + Pi */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                B[y][(2*x+3*y)%5] = ROL64(A[y*5+x], ROT[x][y]);

        /* Chi */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                A[y*5+x] = B[y][x] ^ ((~B[y][(x+1)%5]) & B[y][(x+2)%5]);

        /* Iota */
        A[0] ^= RC[r];
    }
}

/* --------------------------------------------------------------------------
 * Absorb one full rate-block into the state (XOR then permute)
 * -------------------------------------------------------------------------- */

static void absorb_block(sha3_512_ctx *ctx)
{
    size_t i;
    for (i = 0; i < SHA3_512_RATE / 8; i++) {
        uint64_t w = 0;
        int b;
        for (b = 0; b < 8; b++)
            w |= (uint64_t)ctx->buf[i*8+b] << (8*b);
        ctx->state[i] ^= w;
    }
    keccakf(ctx->state);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void sha3_512_init(sha3_512_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void sha3_512_update(sha3_512_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t avail, take;

    while (len > 0) {
        avail = SHA3_512_RATE - ctx->buf_len;
        take  = len < avail ? len : avail;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;

        if (ctx->buf_len == SHA3_512_RATE) {
            absorb_block(ctx);
            ctx->buf_len = 0;
        }
    }
}

void sha3_512_final(sha3_512_ctx *ctx, uint8_t digest[SHA3_512_DIGEST_SIZE])
{
    size_t i;

    /* SHA-3 multi-rate padding: 0x06 … 0x80 */
    memset(ctx->buf + ctx->buf_len, 0, SHA3_512_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len]          = 0x06;
    ctx->buf[SHA3_512_RATE - 1]    |= 0x80;
    absorb_block(ctx);

    /* Squeeze first 64 bytes */
    for (i = 0; i < SHA3_512_DIGEST_SIZE / 8; i++) {
        uint64_t w = ctx->state[i];
        int b;
        for (b = 0; b < 8; b++)
            digest[i*8+b] = (uint8_t)(w >> (8*b));
    }

    memset(ctx, 0, sizeof(*ctx));
}

void sha3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE])
{
    sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_update(&ctx, data, len);
    sha3_512_final(&ctx, digest);
}

int sha3_512_file(const char *path, uint8_t digest[SHA3_512_DIGEST_SIZE])
{
    FILE *fp;
    sha3_512_ctx ctx;
    uint8_t buf[65536];
    size_t n;

    fp = fopen(path, "rb");
    if (!fp) return -1;

    sha3_512_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_512_update(&ctx, buf, n);

    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    sha3_512_final(&ctx, digest);
    return 0;
}

void sha3_512_hex(const uint8_t digest[SHA3_512_DIGEST_SIZE], char hex[SHA3_512_DIGEST_SIZE * 2 + 1])
{
    static const char hc[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < SHA3_512_DIGEST_SIZE; i++) {
        hex[i*2]   = hc[digest[i] >> 4];
        hex[i*2+1] = hc[digest[i] & 0x0f];
    }
    hex[SHA3_512_DIGEST_SIZE * 2] = '\0';
}
