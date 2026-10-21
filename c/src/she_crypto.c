/*
 * SHE crypto: AES-128 (FIPS-197), ECB/CBC modes, AES-CMAC (SP 800-38B) and
 * the Miyaguchi-Preneel KDF used by SHE.
 *
 * Notation used in the comments:
 *   E_K(x)  AES-128 encryption of the 16-byte block x with key K
 *   D_K(x)  AES-128 decryption
 *   ^       bytewise XOR
 *   |       concatenation
 */
#include "she_crypto.h" /* public API of this file */

#include <string.h> /* memcpy, memset */

#include "aes_tables.inc" /* SBOX / INV_SBOX lookup tables */

/* KDF constants. Layout: 01 | 01 (ENC) or 02 (MAC) | "SHE" | 00 | 80 00..00 (MP padding) | B0 (176-bit length). */
const uint8_t SHE_KEY_UPDATE_ENC_C[SHE_BLOCK_SIZE] = { /* derives the encryption keys K1, K3 */
    0x01, 0x01, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
const uint8_t SHE_KEY_UPDATE_MAC_C[SHE_BLOCK_SIZE] = { /* derives the MAC keys K2, K4 */
    0x01, 0x02, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};

/* ---- AES-128 (FIPS-197) ------------------------------------------------ */

#define AES_ROUNDS 10 /* AES-128 uses 10 rounds, so 11 round keys of 16 bytes */

/* xtime(x) = x * 2 in GF(2^8): shift left, reduce with 0x1B if the top bit was set (x^8 = x^4+x^3+x+1). */
static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0x00u)); }

/* gmul(a, b) = a * b in GF(2^8), by shift-and-add ("Russian peasant" multiplication). */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;     /* running product */
    while (b) {        /* for each set bit of b ... */
        if (b & 1u) {  /* ... if the lowest bit is 1 ... */
            r ^= a;    /* ... add (XOR) the current multiple of a */
        }
        a = xtime(a);  /* a = a * 2 for the next bit */
        b >>= 1;       /* move to the next bit of b */
    }
    return r;          /* r = a * b */
}

/*
 * Key expansion: 16-byte key -> 11 round keys (176 bytes), as 44 words w[0..43].
 *   w[i] = w[i-4] ^ SubWord(RotWord(w[i-1])) ^ Rcon[i/4]   when i % 4 == 0
 *   w[i] = w[i-4] ^ w[i-1]                                  otherwise
 */
static void expand_key(const uint8_t key[16], uint8_t rk[16 * (AES_ROUNDS + 1)])
{
    /* Rcon[j] = 2^j in GF(2^8): 01 02 04 08 10 20 40 80 1B 36 */
    static const uint8_t rcon[AES_ROUNDS] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    unsigned i;
    memcpy(rk, key, 16);                             /* round key 0 = the cipher key: w[0..3] */
    for (i = 16; i < 16 * (AES_ROUNDS + 1); i += 4) { /* produce one 4-byte word per iteration */
        uint8_t t[4];
        memcpy(t, &rk[i - 4], 4);                    /* t = w[i-1] */
        if (i % 16 == 0) {                           /* first word of a new round key */
            uint8_t first = t[0];                    /* keep byte 0 for the rotation */
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon[i / 16 - 1]); /* RotWord + SubWord, then XOR Rcon into byte 0 */
            t[1] = SBOX[t[2]];                       /* RotWord moves bytes left by one; SubWord = S-box */
            t[2] = SBOX[t[3]];
            t[3] = SBOX[first];                      /* old byte 0 wraps around to the end */
        }
        rk[i + 0] = rk[i - 16] ^ t[0];               /* w[i] = w[i-4] ^ t */
        rk[i + 1] = rk[i - 15] ^ t[1];
        rk[i + 2] = rk[i - 14] ^ t[2];
        rk[i + 3] = rk[i - 13] ^ t[3];
    }
}

/* AddRoundKey: state = state ^ round key. */
static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        s[i] ^= rk[i]; /* XOR each state byte with the matching round-key byte */
    }
}

/* State is column-major: s[4 * column + row]. Row r is rotated left by r (right by r when inverse). */
static void shift_rows(uint8_t s[16], int inverse)
{
    uint8_t t[16]; /* output state */
    unsigned c, r;
    for (c = 0; c < 4; c++) {
        for (r = 0; r < 4; r++) {
            unsigned src = inverse ? (c + 4 - r) % 4 : (c + r) % 4; /* source column after rotating row r */
            t[4 * c + r] = s[4 * src + r];                        /* move the byte */
        }
    }
    memcpy(s, t, 16); /* copy the shifted state back */
}

/*
 * MixColumns: each column a is multiplied by a fixed matrix in GF(2^8).
 *   forward:  [2 3 1 1]   inverse: [14 11 13  9]
 *             [1 2 3 1]            [ 9 14 11 13]
 *             [1 1 2 3]            [13  9 14 11]
 *             [3 1 1 2]            [11 13  9 14]
 * Each row is the previous row rotated right by one, so only the first row (m0 m1 m2 m3) is stored.
 */
static void mix_columns(uint8_t s[16], int inverse)
{
    /* Coefficients of the first row of the (inverse) MixColumns matrix. */
    const uint8_t m0 = inverse ? 14 : 2, m1 = inverse ? 11 : 3, m2 = inverse ? 13 : 1, m3 = inverse ? 9 : 1;
    unsigned c;
    for (c = 0; c < 4; c++) {
        uint8_t *a = &s[4 * c];                         /* column c */
        uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3]; /* keep the input column */
        a[0] = gmul(a0, m0) ^ gmul(a1, m1) ^ gmul(a2, m2) ^ gmul(a3, m3); /* row 0: m0 m1 m2 m3 */
        a[1] = gmul(a0, m3) ^ gmul(a1, m0) ^ gmul(a2, m1) ^ gmul(a3, m2); /* row 1: m3 m0 m1 m2 */
        a[2] = gmul(a0, m2) ^ gmul(a1, m3) ^ gmul(a2, m0) ^ gmul(a3, m1); /* row 2: m2 m3 m0 m1 */
        a[3] = gmul(a0, m1) ^ gmul(a1, m2) ^ gmul(a2, m3) ^ gmul(a3, m0); /* row 3: m1 m2 m3 m0 */
    }
}

/* SubBytes: replace every byte through the S-box (or the inverse S-box). */
static void sub_bytes(uint8_t s[16], const uint8_t box[256])
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        s[i] = box[s[i]]; /* table lookup */
    }
}

/* E_K(in): AddRoundKey(0); rounds 1..9: SubBytes, ShiftRows, MixColumns, AddRoundKey; round 10 without MixColumns. */
void she_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[16 * (AES_ROUNDS + 1)]; /* 11 round keys */
    uint8_t s[16];                     /* working state */
    unsigned round;
    expand_key(key, rk);               /* derive the round keys */
    memcpy(s, in, 16);                 /* state = plaintext */
    add_round_key(s, rk);              /* initial whitening with round key 0 */
    for (round = 1; round <= AES_ROUNDS; round++) {
        sub_bytes(s, SBOX);            /* non-linear byte substitution */
        shift_rows(s, 0);              /* rotate rows left */
        if (round != AES_ROUNDS) {     /* the last round has no MixColumns */
            mix_columns(s, 0);         /* mix bytes within each column */
        }
        add_round_key(s, &rk[16 * round]); /* XOR the round key */
    }
    memcpy(out, s, 16);                /* ciphertext = final state */
}

/* D_K(in): the encryption steps undone in reverse order, using the inverse S-box and inverse MixColumns. */
void she_aes128_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[16 * (AES_ROUNDS + 1)]; /* 11 round keys */
    uint8_t s[16];                     /* working state */
    unsigned round;
    expand_key(key, rk);               /* same round keys as encryption */
    memcpy(s, in, 16);                 /* state = ciphertext */
    add_round_key(s, &rk[16 * AES_ROUNDS]); /* undo the last AddRoundKey (round 10) */
    for (round = AES_ROUNDS; round-- > 0;) { /* round = 9, 8, ..., 0 */
        shift_rows(s, 1);              /* undo ShiftRows (rotate right) */
        sub_bytes(s, INV_SBOX);        /* undo SubBytes */
        add_round_key(s, &rk[16 * round]); /* undo AddRoundKey of this round */
        if (round != 0) {              /* round 0 had no MixColumns */
            mix_columns(s, 1);         /* undo MixColumns */
        }
    }
    memcpy(out, s, 16);                /* plaintext = final state */
}

/* ---- Modes ------------------------------------------------------------- */

/* dst = a ^ b for one 16-byte block. */
static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < SHE_BLOCK_SIZE; i++) {
        dst[i] = a[i] ^ b[i]; /* XOR byte by byte */
    }
}

/* ECB: C_i = E_K(P_i), each block on its own. */
void she_ecb_encrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) { /* every whole block */
        she_aes128_encrypt_block(key, &in[i], &out[i]);           /* C_i = E_K(P_i) */
    }
}

/* ECB: P_i = D_K(C_i). */
void she_ecb_decrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) { /* every whole block */
        she_aes128_decrypt_block(key, &in[i], &out[i]);           /* P_i = D_K(C_i) */
    }
}

/* CBC: C_0 = IV, C_i = E_K(P_i ^ C_(i-1)). SHE uses IV = 0 for M2. */
void she_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16], t[16]; /* prev = C_(i-1), t = scratch */
    size_t i;
    memcpy(prev, iv, 16);    /* C_0 = IV */
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        xor_block(t, &in[i], prev);             /* t = P_i ^ C_(i-1) */
        she_aes128_encrypt_block(key, t, prev); /* C_i = E_K(t), becomes the next "previous" */
        memcpy(&out[i], prev, 16);              /* output C_i */
    }
}

/* CBC: P_i = D_K(C_i) ^ C_(i-1). */
void she_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16], cur[16], t[16]; /* prev = C_(i-1), cur = C_i (copied so in == out works) */
    size_t i;
    memcpy(prev, iv, 16);             /* C_0 = IV */
    for (i = 0; i + SHE_BLOCK_SIZE <= len; i += SHE_BLOCK_SIZE) {
        memcpy(cur, &in[i], 16);              /* save C_i before out[] may overwrite it */
        she_aes128_decrypt_block(key, cur, t); /* t = D_K(C_i) */
        xor_block(&out[i], t, prev);          /* P_i = t ^ C_(i-1) */
        memcpy(prev, cur, 16);                /* C_i chains into the next block */
    }
}

/* ---- CMAC -------------------------------------------------------------- */

/* out = in << 1 over the whole 128-bit value (big endian). */
static void left_shift(const uint8_t in[16], uint8_t out[16])
{
    unsigned i;
    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t)((in[i] << 1) | (i < 15 ? in[i + 1] >> 7 : 0)); /* carry the top bit of the next byte in */
    }
}

/* dbl(x) = x << 1, XOR 0x87 into the last byte if the top bit of x was 1 (multiply by 2 in GF(2^128)). */
static void derive_subkey(const uint8_t in[16], uint8_t out[16])
{
    left_shift(in, out);   /* x << 1 */
    if (in[0] & 0x80u) {   /* top bit was set ... */
        out[15] ^= 0x87u;  /* ... reduce: XOR R_b = 0x00..87 */
    }
}

/*
 * AES-CMAC (NIST SP 800-38B / RFC 4493):
 *   L = E_K(0), K1' = dbl(L), K2' = dbl(K1')
 *   last block M_n' = M_n ^ K1'           if complete
 *              M_n' = (M_n | 10..0) ^ K2'  otherwise (or for an empty message)
 *   X_0 = 0, X_i = E_K(X_(i-1) ^ M_i), MAC = X_n
 */
void she_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16])
{
    static const uint8_t zero[16] = {0};
    uint8_t l[16], k1[16], k2[16], last[16], state[16] = {0}, t[16]; /* state = X_0 = 0 */
    size_t n = (len + 15) / 16; /* number of blocks, rounding up */
    size_t i;
    int complete;               /* 1 if the last block is a full 16 bytes */

    she_aes128_encrypt_block(key, zero, l); /* L = E_K(0^128) */
    derive_subkey(l, k1);                   /* K1' = dbl(L) */
    derive_subkey(k1, k2);                  /* K2' = dbl(K1') */

    if (n == 0) {          /* empty message ... */
        n = 1;             /* ... is treated as one (padded) block */
        complete = 0;
    } else {
        complete = (len % 16) == 0; /* full last block? */
    }

    if (complete) {
        xor_block(last, &msg[16 * (n - 1)], k1); /* M_n' = M_n ^ K1' */
    } else {
        size_t rem = len - 16 * (n - 1);         /* bytes in the partial last block */
        memset(t, 0, 16);                        /* start with zeros */
        if (rem) {
            memcpy(t, &msg[16 * (n - 1)], rem);  /* copy the partial block */
        }
        t[rem] = 0x80;                           /* append a single 1 bit */
        xor_block(last, t, k2);                  /* M_n' = pad(M_n) ^ K2' */
    }

    for (i = 0; i + 1 < n; i++) {                /* all blocks except the last */
        xor_block(t, state, &msg[16 * i]);       /* t = X_(i-1) ^ M_i */
        she_aes128_encrypt_block(key, t, state); /* X_i = E_K(t) */
    }
    xor_block(t, state, last);                   /* t = X_(n-1) ^ M_n' */
    she_aes128_encrypt_block(key, t, mac);       /* MAC = X_n = E_K(t) */
}

/* ---- Miyaguchi-Preneel and KDF ----------------------------------------- */

/* One MP step: H = E_H(x) ^ x ^ H. */
static void mp_step(uint8_t h[16], const uint8_t x[16])
{
    uint8_t e[16];
    unsigned i;
    she_aes128_encrypt_block(h, x, e); /* e = E_(H_(i-1))(x_i): the running hash is the AES key */
    for (i = 0; i < 16; i++) {
        h[i] = e[i] ^ x[i] ^ h[i];     /* H_i = e ^ x_i ^ H_(i-1) */
    }
}

/* MP(x_1 | ... | x_n) = H_n with H_0 = 0, optionally after SHE padding (1 bit, zeros, 40-bit length). */
void she_miyaguchi_preneel(const uint8_t *msg, size_t len, int pad, uint8_t out[16])
{
    uint8_t h[16] = {0}; /* H_0 = 0^128 */
    uint8_t block[16];
    size_t i;
    size_t full = len / 16; /* number of complete blocks */

    for (i = 0; i < full; i++) {
        mp_step(h, &msg[16 * i]); /* compress each complete block */
    }

    if (pad) {
        /* 1 bit, zeros, then a 40-bit big-endian bit length ending a block. */
        uint64_t bits = (uint64_t)len * 8u; /* message length in bits */
        size_t rem = len % 16;              /* leftover bytes after the complete blocks */
        memset(block, 0, 16);
        memcpy(block, &msg[16 * full], rem); /* leftover message bytes */
        block[rem] = 0x80;                   /* the single 1 bit */
        if (rem + 1 > 11) {                  /* no room for the 5 length bytes in this block ... */
            mp_step(h, block);               /* ... so compress it ... */
            memset(block, 0, 16);            /* ... and put the length in an extra all-zero block */
        }
        for (i = 0; i < 5; i++) {
            block[15 - i] = (uint8_t)(bits >> (8 * i)); /* length in the last 5 bytes, big endian */
        }
        mp_step(h, block);                   /* compress the final padded block */
    }
    memcpy(out, h, 16); /* result = H_n */
}

/* KDF(K, C) = MP(K | C) = E_(H_1)(C) ^ C ^ H_1 with H_1 = E_0(K) ^ K. C already holds the MP padding. */
void she_kdf(const uint8_t key[16], const uint8_t constant[16], uint8_t out[16])
{
    uint8_t buf[32];
    memcpy(buf, key, 16);           /* x_1 = K */
    memcpy(&buf[16], constant, 16); /* x_2 = C (KEY_UPDATE_ENC_C or KEY_UPDATE_MAC_C) */
    she_miyaguchi_preneel(buf, sizeof buf, 0, out); /* MP over the two blocks, no extra padding */
}

/* Constant-time compare: OR together all byte differences, so timing does not reveal where they differ. */
int she_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i]; /* any differing bit stays set */
    }
    return diff == 0;        /* 1 only if every byte matched */
}
