#include "she_crypto.h"

#include <string.h>

#include "aes_tables.inc"

const uint8_t SHE_KEY_UPDATE_ENC_C[SHE_BLOCK_SIZE] = {
    0x01, 0x01, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
const uint8_t SHE_KEY_UPDATE_MAC_C[SHE_BLOCK_SIZE] = {
    0x01, 0x02, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};

/* ---- AES-128 (FIPS-197) ------------------------------------------------ */

#define AES_ROUNDS 10

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0x00u)); }

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1u) {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void expand_key(const uint8_t key[16], uint8_t rk[16 * (AES_ROUNDS + 1)])
{
    static const uint8_t rcon[AES_ROUNDS] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    unsigned i;
    memcpy(rk, key, 16);
    for (i = 16; i < 16 * (AES_ROUNDS + 1); i += 4) {
        uint8_t t[4];
        memcpy(t, &rk[i - 4], 4);
        if (i % 16 == 0) {
            uint8_t first = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon[i / 16 - 1]);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[first];
        }
        rk[i + 0] = rk[i - 16] ^ t[0];
        rk[i + 1] = rk[i - 15] ^ t[1];
        rk[i + 2] = rk[i - 14] ^ t[2];
        rk[i + 3] = rk[i - 13] ^ t[3];
    }
}

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        s[i] ^= rk[i];
    }
}

/* State is column-major: s[4 * column + row]. Row r is rotated left by r. */
static void shift_rows(uint8_t s[16], int inverse)
{
    uint8_t t[16];
    unsigned c, r;
    for (c = 0; c < 4; c++) {
        for (r = 0; r < 4; r++) {
            unsigned src = inverse ? (c + 4 - r) % 4 : (c + r) % 4;
            t[4 * c + r] = s[4 * src + r];
        }
    }
    memcpy(s, t, 16);
}

static void mix_columns(uint8_t s[16], int inverse)
{
    /* Coefficients of the first row of the (inverse) MixColumns matrix. */
    const uint8_t m0 = inverse ? 14 : 2, m1 = inverse ? 11 : 3, m2 = inverse ? 13 : 1, m3 = inverse ? 9 : 1;
    unsigned c;
    for (c = 0; c < 4; c++) {
        uint8_t *a = &s[4 * c];
        uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
        a[0] = gmul(a0, m0) ^ gmul(a1, m1) ^ gmul(a2, m2) ^ gmul(a3, m3);
        a[1] = gmul(a0, m3) ^ gmul(a1, m0) ^ gmul(a2, m1) ^ gmul(a3, m2);
        a[2] = gmul(a0, m2) ^ gmul(a1, m3) ^ gmul(a2, m0) ^ gmul(a3, m1);
        a[3] = gmul(a0, m1) ^ gmul(a1, m2) ^ gmul(a2, m3) ^ gmul(a3, m0);
    }
}

static void sub_bytes(uint8_t s[16], const uint8_t box[256])
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        s[i] = box[s[i]];
    }
}

void she_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[16 * (AES_ROUNDS + 1)];
    uint8_t s[16];
    unsigned round;
    expand_key(key, rk);
    memcpy(s, in, 16);
    add_round_key(s, rk);
    for (round = 1; round <= AES_ROUNDS; round++) {
        sub_bytes(s, SBOX);
        shift_rows(s, 0);
        if (round != AES_ROUNDS) {
            mix_columns(s, 0);
        }
        add_round_key(s, &rk[16 * round]);
    }
    memcpy(out, s, 16);
}

void she_aes128_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[16 * (AES_ROUNDS + 1)];
    uint8_t s[16];
    unsigned round;
    expand_key(key, rk);
    memcpy(s, in, 16);
    add_round_key(s, &rk[16 * AES_ROUNDS]);
    for (round = AES_ROUNDS; round-- > 0;) {
        shift_rows(s, 1);
        sub_bytes(s, INV_SBOX);
        add_round_key(s, &rk[16 * round]);
        if (round != 0) {
            mix_columns(s, 1);
        }
    }
    memcpy(out, s, 16);
}

/* ---- Modes ------------------------------------------------------------- */

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < SHE_BLOCK_SIZE; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

void she_ecb_encrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        she_aes128_encrypt_block(key, &in[i], &out[i]);
    }
}

void she_ecb_decrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        she_aes128_decrypt_block(key, &in[i], &out[i]);
    }
}

void she_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16], t[16];
    size_t i;
    memcpy(prev, iv, 16);
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        xor_block(t, &in[i], prev);
        she_aes128_encrypt_block(key, t, prev);
        memcpy(&out[i], prev, 16);
    }
}

void she_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16], cur[16], t[16];
    size_t i;
    memcpy(prev, iv, 16);
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        memcpy(cur, &in[i], 16);
        she_aes128_decrypt_block(key, cur, t);
        xor_block(&out[i], t, prev);
        memcpy(prev, cur, 16);
    }
}

/* ---- CMAC -------------------------------------------------------------- */

static void left_shift(const uint8_t in[16], uint8_t out[16])
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t)((in[i] << 1) | (i < 15 ? in[i + 1] >> 7 : 0));
    }
}

static void derive_subkey(const uint8_t in[16], uint8_t out[16])
{
    left_shift(in, out);
    if (in[0] & 0x80u) {
        out[15] ^= 0x87u;
    }
}

void she_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16])
{
    static const uint8_t zero[16] = {0};
    uint8_t l[16], k1[16], k2[16], last[16], state[16] = {0}, t[16];
    size_t n = (len + 15) / 16; /* number of blocks */
    size_t i;
    int complete;

    she_aes128_encrypt_block(key, zero, l);
    derive_subkey(l, k1);
    derive_subkey(k1, k2);

    if (n == 0) {
        n = 1;
        complete = 0;
    } else {
        complete = (len % 16) == 0;
    }

    if (complete) {
        xor_block(last, &msg[16 * (n - 1)], k1);
    } else {
        size_t rem = len - 16 * (n - 1);
        memset(t, 0, 16);
        if (rem) {
            memcpy(t, &msg[16 * (n - 1)], rem);
        }
        t[rem] = 0x80;
        xor_block(last, t, k2);
    }

    for (i = 0; i + 1 < n; i++) {
        xor_block(t, state, &msg[16 * i]);
        she_aes128_encrypt_block(key, t, state);
    }
    xor_block(t, state, last);
    she_aes128_encrypt_block(key, t, mac);
}

/* ---- Miyaguchi-Preneel and KDF ----------------------------------------- */

static void mp_step(uint8_t h[16], const uint8_t x[16])
{
    uint8_t e[16];
    unsigned i;
    she_aes128_encrypt_block(h, x, e);
    for (i = 0; i < 16; i++) {
        h[i] = e[i] ^ x[i] ^ h[i];
    }
}

void she_miyaguchi_preneel(const uint8_t *msg, size_t len, int pad, uint8_t out[16])
{
    uint8_t h[16] = {0};
    uint8_t block[16];
    size_t i;
    size_t full = len / 16;

    for (i = 0; i < full; i++) {
        mp_step(h, &msg[16 * i]);
    }

    if (pad) {
        /* 1 bit, zeros, then a 40-bit big-endian bit length ending a block. */
        uint64_t bits = (uint64_t)len * 8u;
        size_t rem = len % 16;
        memset(block, 0, 16);
        memcpy(block, &msg[16 * full], rem);
        block[rem] = 0x80;
        if (rem + 1 > 11) {
            mp_step(h, block);
            memset(block, 0, 16);
        }
        for (i = 0; i < 5; i++) {
            block[15 - i] = (uint8_t)(bits >> (8 * i));
        }
        mp_step(h, block);
    }
    memcpy(out, h, 16);
}

void she_kdf(const uint8_t key[16], const uint8_t constant[16], uint8_t out[16])
{
    uint8_t buf[32];
    memcpy(buf, key, 16);
    memcpy(&buf[16], constant, 16);
    she_miyaguchi_preneel(buf, sizeof buf, 0, out);
}

int she_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}
