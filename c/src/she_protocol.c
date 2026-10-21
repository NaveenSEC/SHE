/*
 * Host side of the SHE CMD_LOAD_KEY protocol: build M1..M5, decode M2/M4, verify the response.
 * See docs/PROTOCOL.md for the formulas with worked values.
 *
 * Bit positions inside a 128-bit block are counted from 127 (first byte, MSB) down to 0.
 * "C_ID(28) | F_ID(5) | 0(95)" puts C_ID in bits 127..100, F_ID in bits 99..95, zeros below.
 * Because 28 + 4 = 32, the first 4 bytes of such a block hold C_ID and the top 4 bits of F_ID,
 * and the top bit of byte 4 holds the lowest bit of F_ID.
 */
#include <string.h> /* memcpy, memcmp */

#include "she.h"    /* public API */

/* Name of a status code, for printing. */
const char *she_status_name(she_status_t status)
{
    switch (status) {
    case SHE_OK: return "SHE_OK";                                         /* success */
    case SHE_ERC_KEY_INVALID: return "ERC_KEY_INVALID";                   /* bad slot or AuthID */
    case SHE_ERC_KEY_EMPTY: return "ERC_KEY_EMPTY";                       /* authorizing slot empty */
    case SHE_ERC_KEY_WRITE_PROTECTED: return "ERC_KEY_WRITE_PROTECTED";   /* slot is write protected */
    case SHE_ERC_KEY_UPDATE_ERROR: return "ERC_KEY_UPDATE_ERROR";         /* bad M3, UID or counter */
    case SHE_ERR_PARAM: return "ERR_PARAM";                               /* bad library argument */
    }
    return "UNKNOWN"; /* not a known status value */
}

/* Name of a key slot ID (0x0..0xE), for printing and for parsing slot names in the CLI. */
const char *she_slot_name(int slot)
{
    static const char *const names[SHE_NUM_SLOTS] = { /* index = slot ID */
        "SECRET_KEY", "MASTER_ECU_KEY", "BOOT_MAC_KEY", "BOOT_MAC", "KEY_1", "KEY_2", "KEY_3", "KEY_4",
        "KEY_5",      "KEY_6",          "KEY_7",        "KEY_8",    "KEY_9", "KEY_10", "RAM_KEY"};
    return (slot >= 0 && slot < (int)SHE_NUM_SLOTS) ? names[slot] : "INVALID"; /* bounds-checked lookup */
}

/* F_ID = WP<<4 | BP<<3 | DP<<2 | KU<<1 | WC */
uint8_t she_flags_to_bits(const she_flags_t *f)
{
    return (uint8_t)((f->write_protection << 4) |    /* bit 4: write protection */
                     (f->boot_protection << 3) |     /* bit 3: boot protection */
                     (f->debugger_protection << 2) | /* bit 2: debugger protection */
                     (f->key_usage << 1) |           /* bit 1: key usage */
                     f->wildcard);                   /* bit 0: wildcard */
}

/* Inverse of she_flags_to_bits. */
she_flags_t she_flags_from_bits(uint8_t bits)
{
    she_flags_t f;
    f.write_protection = (bits & 0x10u) != 0;    /* bit 4 = 0b10000 */
    f.boot_protection = (bits & 0x08u) != 0;     /* bit 3 = 0b01000 */
    f.debugger_protection = (bits & 0x04u) != 0; /* bit 2 = 0b00100 */
    f.key_usage = (bits & 0x02u) != 0;           /* bit 1 = 0b00010 */
    f.wildcard = (bits & 0x01u) != 0;            /* bit 0 = 0b00001 */
    return f;
}

/* Store a 32-bit value as 4 big-endian bytes (most significant byte first). */
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); /* bits 31..24 */
    p[1] = (uint8_t)(v >> 16); /* bits 23..16 */
    p[2] = (uint8_t)(v >> 8);  /* bits 15..8 */
    p[3] = (uint8_t)v;         /* bits 7..0 */
}

/* Read 4 big-endian bytes as a 32-bit value. */
static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* M1 = UID(120) | ID(4) | AuthID(4); the last byte is (ID << 4) | AuthID. */
void she_build_m1(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, uint8_t m1[16])
{
    memcpy(m1, uid, SHE_UID_SIZE);                                 /* bytes 0..14 = UID */
    m1[15] = (uint8_t)(((key_id & 0xF) << 4) | (auth_id & 0xF));   /* byte 15: ID in high nibble, AuthID in low */
}

/* M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new ), K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C). */
static void build_m2(const uint8_t auth_key[SHE_KEY_SIZE], uint32_t counter, uint8_t flag_bits,
                     const uint8_t new_key[SHE_KEY_SIZE], uint8_t m2[32])
{
    static const uint8_t iv[16] = {0}; /* SHE uses IV = 0 */
    uint8_t k1[16], plain[32] = {0};   /* plaintext = block 1 | block 2, zero-filled */
    /* C_ID(28) | F_ID(5) | 0(95): the top 32 bits hold the counter and F_ID[4:1], bit 95 holds F_ID[0]. */
    put_be32(plain, (counter << 4) | (uint32_t)(flag_bits >> 1)); /* bytes 0..3 = C_ID << 4 | F_ID >> 1 */
    plain[4] = (uint8_t)((flag_bits & 1u) << 7);                  /* byte 4 MSB = F_ID bit 0 */
    memcpy(&plain[16], new_key, SHE_KEY_SIZE);                    /* block 2 = KEY_new */
    she_kdf(auth_key, SHE_KEY_UPDATE_ENC_C, k1);                  /* K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) */
    she_cbc_encrypt(k1, iv, plain, m2, sizeof plain);             /* M2 = CBC-encrypt(K1, IV=0, plaintext) */
}

/* M3 = CMAC,K2( M1 | M2 ), K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C). */
void she_build_m3(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m1[16], const uint8_t m2[32], uint8_t m3[16])
{
    uint8_t k2[16], buf[48];                     /* buf = M1 | M2 (16 + 32 bytes) */
    she_kdf(auth_key, SHE_KEY_UPDATE_MAC_C, k2); /* K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) */
    memcpy(buf, m1, 16);                         /* first M1 ... */
    memcpy(&buf[16], m2, 32);                    /* ... then M2 */
    she_cmac(k2, buf, sizeof buf, m3);           /* M3 = CMAC(K2, M1 | M2) */
}

/* M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) ), K3 = KDF(KEY_new, KEY_UPDATE_ENC_C). */
void she_build_m4(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t new_key[SHE_KEY_SIZE],
                  uint32_t counter, uint8_t m4[32])
{
    uint8_t k3[16], block[16] = {0};               /* counter block, zero-filled */
    she_build_m1(uid, key_id, auth_id, m4);        /* first 16 bytes: same layout as M1 */
    /* C_ID(28) | 1 | 0(99): the "1" is bit 99 = bit 3 of the first 32-bit word, i.e. 0x8. */
    put_be32(block, (counter << 4) | 0x8u);        /* bytes 0..3 = C_ID << 4 | 1000b */
    she_kdf(new_key, SHE_KEY_UPDATE_ENC_C, k3);    /* K3 = KDF(KEY_new, KEY_UPDATE_ENC_C): from the NEW key */
    she_ecb_encrypt(k3, block, &m4[16], 16);       /* last 16 bytes = E_K3(counter block) */
}

/* M5 = CMAC,K4( M4 ), K4 = KDF(KEY_new, KEY_UPDATE_MAC_C). */
void she_build_m5(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint8_t m5[16])
{
    uint8_t k4[16];
    she_kdf(new_key, SHE_KEY_UPDATE_MAC_C, k4); /* K4 = KDF(KEY_new, KEY_UPDATE_MAC_C): from the NEW key */
    she_cmac(k4, m4, 32, m5);                   /* M5 = CMAC(K4, M4) */
}

/* Build all five messages: the request M1..M3 and the expected response M4, M5. */
she_status_t she_build_key_update(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id,
                                  const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t new_key[SHE_KEY_SIZE],
                                  uint32_t counter, const she_flags_t *flags, she_messages_t *out)
{
    she_flags_t none = {false, false, false, false, false}; /* used when flags == NULL */
    /* Reject NULL pointers, a counter wider than 28 bits and IDs that do not fit in 4 bits. */
    if (!uid || !auth_key || !new_key || !out || counter > SHE_MAX_COUNTER || key_id < 0 || key_id > 0xF ||
        auth_id < 0 || auth_id > 0xF) {
        return SHE_ERR_PARAM;
    }
    she_build_m1(uid, key_id, auth_id, out->m1);                                     /* M1 = UID | ID | AuthID */
    build_m2(auth_key, counter, she_flags_to_bits(flags ? flags : &none), new_key, out->m2); /* M2 */
    she_build_m3(auth_key, out->m1, out->m2, out->m3);                               /* M3 = CMAC,K2(M1 | M2) */
    she_build_m4(uid, key_id, auth_id, new_key, counter, out->m4);                   /* M4 (expected) */
    she_build_m5(new_key, out->m4, out->m5);                                         /* M5 = CMAC,K4(M4) */
    return SHE_OK;
}

/* Split M1 into UID, ID and AuthID. */
void she_parse_m1(const uint8_t m1[16], uint8_t uid[SHE_UID_SIZE], int *key_id, int *auth_id)
{
    memcpy(uid, m1, SHE_UID_SIZE); /* bytes 0..14 = UID */
    *key_id = m1[15] >> 4;         /* high nibble of byte 15 = ID */
    *auth_id = m1[15] & 0xF;       /* low nibble of byte 15 = AuthID */
}

/* Decrypt M2 with K1 and split it into C_ID, F_ID and KEY_new (what the SHE module does). */
void she_decode_m2(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m2[32], she_m2_plain_t *out)
{
    static const uint8_t iv[16] = {0}; /* IV = 0 */
    uint8_t k1[16], plain[32];
    uint32_t word;                     /* first 32 bits of block 1 */
    she_kdf(auth_key, SHE_KEY_UPDATE_ENC_C, k1);        /* K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) */
    she_cbc_decrypt(k1, iv, m2, plain, sizeof plain);   /* plaintext = block 1 | KEY_new */
    word = get_be32(plain);                             /* C_ID(28) | F_ID[4:1](4) */
    out->counter = word >> 4;                           /* C_ID = top 28 bits */
    out->flags = she_flags_from_bits((uint8_t)(((word & 0xFu) << 1) | (plain[4] >> 7))); /* F_ID = 4 bits + bit 95 */
    memcpy(out->key, &plain[16], SHE_KEY_SIZE);         /* KEY_new = block 2 */
}

/* Decrypt the second half of M4 with K3 and return C_ID; SHE_ERR_PARAM if the "1 then zeros" marker is wrong. */
she_status_t she_decode_m4_counter(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint32_t *counter)
{
    static const uint8_t zero[12] = {0};
    uint8_t k3[16], block[16];
    uint32_t word;
    she_kdf(new_key, SHE_KEY_UPDATE_ENC_C, k3);  /* K3 = KDF(KEY_new, KEY_UPDATE_ENC_C) */
    she_ecb_decrypt(k3, &m4[16], block, 16);     /* counter block = D_K3(M4 bytes 16..31) */
    word = get_be32(block);                      /* C_ID(28) | 1000b */
    if ((word & 0xFu) != 0x8u || memcmp(&block[4], zero, sizeof zero) != 0) { /* expect 1 followed by 99 zeros */
        return SHE_ERR_PARAM;                    /* wrong key, or not a valid M4 */
    }
    *counter = word >> 4;                        /* C_ID = top 28 bits */
    return SHE_OK;
}

/* The module's M4 and M5 must equal what the host computed. Bitwise & so both comparisons always run. */
bool she_verify_response(const she_messages_t *expected, const uint8_t m4[32], const uint8_t m5[16])
{
    return (she_ct_equal(expected->m4, m4, 32) & she_ct_equal(expected->m5, m5, 16)) != 0;
}
