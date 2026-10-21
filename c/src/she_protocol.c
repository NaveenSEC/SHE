#include <string.h>

#include "she.h"

const char *she_status_name(she_status_t status)
{
    switch (status) {
    case SHE_OK: return "SHE_OK";
    case SHE_ERC_KEY_INVALID: return "ERC_KEY_INVALID";
    case SHE_ERC_KEY_EMPTY: return "ERC_KEY_EMPTY";
    case SHE_ERC_KEY_WRITE_PROTECTED: return "ERC_KEY_WRITE_PROTECTED";
    case SHE_ERC_KEY_UPDATE_ERROR: return "ERC_KEY_UPDATE_ERROR";
    case SHE_ERR_PARAM: return "ERR_PARAM";
    }
    return "UNKNOWN";
}

const char *she_slot_name(int slot)
{
    static const char *const names[SHE_NUM_SLOTS] = {
        "SECRET_KEY", "MASTER_ECU_KEY", "BOOT_MAC_KEY", "BOOT_MAC", "KEY_1", "KEY_2", "KEY_3", "KEY_4",
        "KEY_5",      "KEY_6",          "KEY_7",        "KEY_8",    "KEY_9", "KEY_10", "RAM_KEY"};
    return (slot >= 0 && slot < (int)SHE_NUM_SLOTS) ? names[slot] : "INVALID";
}

uint8_t she_flags_to_bits(const she_flags_t *f)
{
    return (uint8_t)((f->write_protection << 4) | (f->boot_protection << 3) | (f->debugger_protection << 2) |
                     (f->key_usage << 1) | f->wildcard);
}

she_flags_t she_flags_from_bits(uint8_t bits)
{
    she_flags_t f;
    f.write_protection = (bits & 0x10u) != 0;
    f.boot_protection = (bits & 0x08u) != 0;
    f.debugger_protection = (bits & 0x04u) != 0;
    f.key_usage = (bits & 0x02u) != 0;
    f.wildcard = (bits & 0x01u) != 0;
    return f;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* M1 = UID(120) | ID(4) | AuthID(4); the last byte is (ID << 4) | AuthID. */
void she_build_m1(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, uint8_t m1[16])
{
    memcpy(m1, uid, SHE_UID_SIZE);
    m1[15] = (uint8_t)(((key_id & 0xF) << 4) | (auth_id & 0xF));
}

/* M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new ), K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C). */
static void build_m2(const uint8_t auth_key[SHE_KEY_SIZE], uint32_t counter, uint8_t flag_bits,
                     const uint8_t new_key[SHE_KEY_SIZE], uint8_t m2[32])
{
    static const uint8_t iv[16] = {0};
    uint8_t k1[16], plain[32] = {0};
    /* C_ID(28) | F_ID(5) | 0(95): the top 32 bits hold the counter and F_ID[4:1], bit 95 holds F_ID[0]. */
    put_be32(plain, (counter << 4) | (uint32_t)(flag_bits >> 1));
    plain[4] = (uint8_t)((flag_bits & 1u) << 7);
    memcpy(&plain[16], new_key, SHE_KEY_SIZE);
    she_kdf(auth_key, SHE_KEY_UPDATE_ENC_C, k1);
    she_cbc_encrypt(k1, iv, plain, m2, sizeof plain);
}

/* M3 = CMAC,K2( M1 | M2 ), K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C). */
void she_build_m3(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m1[16], const uint8_t m2[32], uint8_t m3[16])
{
    uint8_t k2[16], buf[48];
    she_kdf(auth_key, SHE_KEY_UPDATE_MAC_C, k2);
    memcpy(buf, m1, 16);
    memcpy(&buf[16], m2, 32);
    she_cmac(k2, buf, sizeof buf, m3);
}

/* M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) ), K3 = KDF(KEY_new, KEY_UPDATE_ENC_C). */
void she_build_m4(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t new_key[SHE_KEY_SIZE],
                  uint32_t counter, uint8_t m4[32])
{
    uint8_t k3[16], block[16] = {0};
    she_build_m1(uid, key_id, auth_id, m4);
    /* C_ID(28) | 1 | 0(99) */
    put_be32(block, (counter << 4) | 0x8u);
    she_kdf(new_key, SHE_KEY_UPDATE_ENC_C, k3);
    she_ecb_encrypt(k3, block, &m4[16], 16);
}

/* M5 = CMAC,K4( M4 ), K4 = KDF(KEY_new, KEY_UPDATE_MAC_C). */
void she_build_m5(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint8_t m5[16])
{
    uint8_t k4[16];
    she_kdf(new_key, SHE_KEY_UPDATE_MAC_C, k4);
    she_cmac(k4, m4, 32, m5);
}

she_status_t she_build_key_update(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id,
                                  const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t new_key[SHE_KEY_SIZE],
                                  uint32_t counter, const she_flags_t *flags, she_messages_t *out)
{
    she_flags_t none = {false, false, false, false, false};
    if (!uid || !auth_key || !new_key || !out || counter > SHE_MAX_COUNTER || key_id < 0 || key_id > 0xF ||
        auth_id < 0 || auth_id > 0xF) {
        return SHE_ERR_PARAM;
    }
    she_build_m1(uid, key_id, auth_id, out->m1);
    build_m2(auth_key, counter, she_flags_to_bits(flags ? flags : &none), new_key, out->m2);
    she_build_m3(auth_key, out->m1, out->m2, out->m3);
    she_build_m4(uid, key_id, auth_id, new_key, counter, out->m4);
    she_build_m5(new_key, out->m4, out->m5);
    return SHE_OK;
}

void she_parse_m1(const uint8_t m1[16], uint8_t uid[SHE_UID_SIZE], int *key_id, int *auth_id)
{
    memcpy(uid, m1, SHE_UID_SIZE);
    *key_id = m1[15] >> 4;
    *auth_id = m1[15] & 0xF;
}

void she_decode_m2(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m2[32], she_m2_plain_t *out)
{
    static const uint8_t iv[16] = {0};
    uint8_t k1[16], plain[32];
    uint32_t word;
    she_kdf(auth_key, SHE_KEY_UPDATE_ENC_C, k1);
    she_cbc_decrypt(k1, iv, m2, plain, sizeof plain);
    word = get_be32(plain);
    out->counter = word >> 4;
    out->flags = she_flags_from_bits((uint8_t)(((word & 0xFu) << 1) | (plain[4] >> 7)));
    memcpy(out->key, &plain[16], SHE_KEY_SIZE);
}

she_status_t she_decode_m4_counter(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint32_t *counter)
{
    static const uint8_t zero[12] = {0};
    uint8_t k3[16], block[16];
    uint32_t word;
    she_kdf(new_key, SHE_KEY_UPDATE_ENC_C, k3);
    she_ecb_decrypt(k3, &m4[16], block, 16);
    word = get_be32(block);
    if ((word & 0xFu) != 0x8u || memcmp(&block[4], zero, sizeof zero) != 0) {
        return SHE_ERR_PARAM;
    }
    *counter = word >> 4;
    return SHE_OK;
}

bool she_verify_response(const she_messages_t *expected, const uint8_t m4[32], const uint8_t m5[16])
{
    return (she_ct_equal(expected->m4, m4, 32) & she_ct_equal(expected->m5, m5, 16)) != 0;
}
