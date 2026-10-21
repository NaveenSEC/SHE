/*
 * Test suite. Run with no argument for every group, or with a group name
 * (crypto, protocol, emulator) as CTest does.
 */
#include <stdio.h>
#include <string.h>

#include "she.h"

static int failures;
static int checks;

#define CHECK(cond)                                                                                                \
    do {                                                                                                           \
        checks++;                                                                                                  \
        if (!(cond)) {                                                                                             \
            failures++;                                                                                            \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                                 \
        }                                                                                                          \
    } while (0)

#define CHECK_HEX(buf, len, hex) CHECK(hex_equal((buf), (len), (hex)))
#define CHECK_STATUS(expr, expected) CHECK((expr) == (expected))

static void from_hex(const char *hex, uint8_t *out)
{
    size_t i, n = strlen(hex) / 2;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(&hex[2 * i], "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int hex_equal(const uint8_t *buf, size_t len, const char *hex)
{
    uint8_t expected[128];
    if (strlen(hex) != 2 * len) {
        return 0;
    }
    from_hex(hex, expected);
    return memcmp(buf, expected, len) == 0;
}

/* ---- Fixtures ---------------------------------------------------------- */

static const she_flags_t NO_FLAGS = {false, false, false, false, false};
static uint8_t UID[SHE_UID_SIZE], OTHER_UID[SHE_UID_SIZE], WILDCARD[SHE_UID_SIZE];
static uint8_t MASTER_KEY[16], NEW_KEY[16], ZERO_KEY[16], ALT_KEY[16];

static void init_fixtures(void)
{
    int i;
    memset(UID, 0, sizeof UID);
    UID[14] = 0x01;
    memset(OTHER_UID, 0, sizeof OTHER_UID);
    OTHER_UID[14] = 0x02;
    memset(WILDCARD, 0, sizeof WILDCARD);
    memset(ZERO_KEY, 0, sizeof ZERO_KEY);
    for (i = 0; i < 16; i++) {
        MASTER_KEY[i] = (uint8_t)i;
        NEW_KEY[i] = (uint8_t)(15 - i);
        ALT_KEY[i] = (uint8_t)(32 + i);
    }
}

static void new_she(she_emulator_t *emu)
{
    she_emu_init(emu, UID);
    she_emu_provision(emu, SHE_MASTER_ECU_KEY, MASTER_KEY, 0, NULL);
}

static she_messages_t make(const uint8_t *uid, int key_id, int auth_id, const uint8_t *auth_key,
                           const uint8_t *new_key, uint32_t counter, const she_flags_t *flags)
{
    she_messages_t m;
    memset(&m, 0, sizeof m);
    CHECK_STATUS(she_build_key_update(uid, key_id, auth_id, auth_key, new_key, counter, flags, &m), SHE_OK);
    return m;
}

static she_messages_t spec_update(uint32_t counter, const uint8_t *new_key)
{
    return make(UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, MASTER_KEY, new_key, counter, &NO_FLAGS);
}

static she_status_t send(she_emulator_t *emu, const she_messages_t *m, uint8_t m4[32], uint8_t m5[16])
{
    return she_emu_load_key(emu, m->m1, m->m2, m->m3, m4, m5);
}

/* Send and require the module's answer to match what the host expects. */
static void send_ok(she_emulator_t *emu, const she_messages_t *m)
{
    uint8_t m4[32], m5[16];
    CHECK_STATUS(send(emu, m, m4, m5), SHE_OK);
    CHECK(she_verify_response(m, m4, m5));
}

static void expect(she_emulator_t *emu, const she_messages_t *m, she_status_t code)
{
    uint8_t m4[32], m5[16];
    CHECK_STATUS(send(emu, m, m4, m5), code);
}

/* ---- Crypto ------------------------------------------------------------ */

static const char *NIST_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *NIST_PT = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                             "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

static void test_crypto(void)
{
    uint8_t key[16], pt[64], ct[64], back[64], iv[16], mac[16], out[16];
    static const struct {
        size_t len;
        const char *tag;
    } cmac_vectors[] = {
        {0, "bb1d6929e95937287fa37d129b756746"},
        {16, "070a16b46b4d4144f79bdd9dd04a287c"},
        {40, "dfa66747de9ae63030ca32611497c827"},
        {64, "51f0bebf7e3b9d92fc49741779363cfe"},
    };
    size_t i;

    from_hex(NIST_KEY, key);
    from_hex(NIST_PT, pt);

    /* NIST SP 800-38A F.1.1 / F.1.2: ECB-AES128 */
    she_ecb_encrypt(key, pt, ct, 64);
    CHECK_HEX(ct, 64, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                      "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
    she_ecb_decrypt(key, ct, back, 64);
    CHECK(memcmp(back, pt, 64) == 0);

    /* NIST SP 800-38A F.2.1 / F.2.2: CBC-AES128 */
    for (i = 0; i < 16; i++) {
        iv[i] = (uint8_t)i;
    }
    she_cbc_encrypt(key, iv, pt, ct, 64);
    CHECK_HEX(ct, 64, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                      "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
    she_cbc_decrypt(key, iv, ct, back, 64);
    CHECK(memcmp(back, pt, 64) == 0);

    /* RFC 4493 AES-CMAC */
    for (i = 0; i < sizeof cmac_vectors / sizeof cmac_vectors[0]; i++) {
        she_cmac(key, pt, cmac_vectors[i].len, mac);
        CHECK_HEX(mac, 16, cmac_vectors[i].tag);
    }

    /* SHE spec Miyaguchi-Preneel example (with padding) */
    she_miyaguchi_preneel(pt, 32, 1, out);
    CHECK_HEX(out, 16, "c7277a0dc1fb853b5f4d9cbd26be40c6");

    /* SHE spec KDF example: K1 for the CMD_LOAD_KEY example */
    she_kdf(MASTER_KEY, SHE_KEY_UPDATE_ENC_C, out);
    CHECK_HEX(out, 16, "118a46447a770d87828a69c222e2d17e");
    she_kdf(MASTER_KEY, SHE_KEY_UPDATE_MAC_C, mac);
    CHECK(memcmp(out, mac, 16) != 0);

    CHECK(she_ct_equal(pt, pt, 64));
    CHECK(!she_ct_equal(pt, ct, 64));
}

/* ---- Protocol ---------------------------------------------------------- */

static void test_protocol(void)
{
    she_messages_t m = spec_update(1, NEW_KEY), bad;
    she_m2_plain_t plain;
    she_flags_t flags = {true, false, false, true, false};
    uint8_t uid[SHE_UID_SIZE], zeros[16] = {0};
    uint32_t counter = 0;
    int key_id, auth_id;
    unsigned bits;

    /* Example from the SHE functional specification (CMD_LOAD_KEY). */
    CHECK_HEX(m.m1, 16, "00000000000000000000000000000141");
    CHECK_HEX(m.m2, 32, "2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3");
    CHECK_HEX(m.m3, 16, "b9d745e5ace7d41860bc63c2b9f5bb46");
    CHECK_HEX(m.m4, 32, "00000000000000000000000000000141b472e8d8727d70d57295e74849a27917");
    CHECK_HEX(m.m5, 16, "820d8d95dc11b4668878160cb2a4e23e");

    for (bits = 0; bits < 32; bits++) {
        she_flags_t f = she_flags_from_bits((uint8_t)bits);
        CHECK(she_flags_to_bits(&f) == bits);
    }
    {
        she_flags_t wp = {true, false, false, false, false}, wc = {false, false, false, false, true};
        CHECK(she_flags_to_bits(&wp) == 0x10);
        CHECK(she_flags_to_bits(&wc) == 0x01);
    }

    she_parse_m1(m.m1, uid, &key_id, &auth_id);
    CHECK(memcmp(uid, UID, sizeof uid) == 0 && key_id == SHE_KEY_1 && auth_id == SHE_MASTER_ECU_KEY);

    bad = make(UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, 0x0ABCDEF, &flags);
    she_decode_m2(MASTER_KEY, bad.m2, &plain);
    CHECK(plain.counter == 0x0ABCDEF);
    CHECK(she_flags_to_bits(&plain.flags) == she_flags_to_bits(&flags));
    CHECK(memcmp(plain.key, NEW_KEY, 16) == 0);

    CHECK_STATUS(she_decode_m4_counter(NEW_KEY, m.m4, &counter), SHE_OK);
    CHECK(counter == 1);
    CHECK_STATUS(she_decode_m4_counter(MASTER_KEY, m.m4, &counter), SHE_ERR_PARAM);

    CHECK(she_verify_response(&m, m.m4, m.m5));
    CHECK(!she_verify_response(&m, m.m4, zeros));

    CHECK_STATUS(she_build_key_update(UID, 4, 1, MASTER_KEY, NEW_KEY, SHE_MAX_COUNTER + 1u, NULL, &bad),
                 SHE_ERR_PARAM);
    CHECK_STATUS(she_build_key_update(UID, 16, 1, MASTER_KEY, NEW_KEY, 1, NULL, &bad), SHE_ERR_PARAM);
    CHECK_STATUS(she_build_key_update(NULL, 4, 1, MASTER_KEY, NEW_KEY, 1, NULL, &bad), SHE_ERR_PARAM);
    /* NULL flags means "no flags set". */
    CHECK_STATUS(she_build_key_update(UID, 4, 1, MASTER_KEY, NEW_KEY, 1, NULL, &bad), SHE_OK);
    CHECK(memcmp(bad.m2, m.m2, 32) == 0);

    CHECK(strcmp(she_slot_name(SHE_RAM_KEY), "RAM_KEY") == 0);
    CHECK(strcmp(she_slot_name(15), "INVALID") == 0);
    CHECK(strcmp(she_status_name(SHE_ERC_KEY_EMPTY), "ERC_KEY_EMPTY") == 0);
}

/* ---- Emulator ---------------------------------------------------------- */

static void test_emulator(void)
{
    she_emulator_t emu;
    she_messages_t m;
    uint8_t m4[32], m5[16];
    she_flags_t wp = {true, false, false, false, false}, wc = {false, false, false, false, true};

    /* Spec update is accepted and stored. */
    new_she(&emu);
    m = spec_update(1, NEW_KEY);
    send_ok(&emu, &m);
    CHECK(memcmp(emu.slots[SHE_KEY_1].key, NEW_KEY, 16) == 0 && emu.slots[SHE_KEY_1].counter == 1);

    /* Replay is rejected. */
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);

    /* Tampered M2 / M3. */
    new_she(&emu);
    m = spec_update(1, NEW_KEY);
    m.m2[0] ^= 1;
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);
    m = spec_update(1, NEW_KEY);
    memset(m.m3, 0, 16);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);

    /* Wrong authorizing key. */
    m = make(UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, ZERO_KEY, NEW_KEY, 1, &NO_FLAGS);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);

    /* Counter must strictly increase. */
    new_she(&emu);
    m = spec_update(5, NEW_KEY);
    send_ok(&emu, &m);
    m = spec_update(5, ZERO_KEY);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);
    m = spec_update(6, ZERO_KEY);
    send_ok(&emu, &m);
    CHECK(emu.slots[SHE_KEY_1].counter == 6);

    /* UID mismatch. */
    new_she(&emu);
    m = make(OTHER_UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, 1, &NO_FLAGS);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);

    /* Wildcard UID needs the slot's wildcard flag; the module answers with its real UID. */
    m = make(WILDCARD, SHE_KEY_1, SHE_MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, 2, &NO_FLAGS);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);
    she_emu_provision(&emu, SHE_KEY_1, ZERO_KEY, 1, &wc);
    CHECK_STATUS(send(&emu, &m, m4, m5), SHE_OK);
    CHECK(memcmp(m4, UID, SHE_UID_SIZE) == 0);

    /* Write protection. */
    new_she(&emu);
    m = make(UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, 1, &wp);
    send_ok(&emu, &m);
    m = spec_update(2, ZERO_KEY);
    expect(&emu, &m, SHE_ERC_KEY_WRITE_PROTECTED);

    /* Unauthorized AuthID (KEY_2 may not update KEY_1). */
    new_she(&emu);
    she_emu_provision(&emu, SHE_KEY_2, MASTER_KEY, 0, NULL);
    m = make(UID, SHE_KEY_1, SHE_KEY_2, MASTER_KEY, NEW_KEY, 1, &NO_FLAGS);
    expect(&emu, &m, SHE_ERC_KEY_INVALID);

    /* SECRET_KEY can never be loaded. */
    m = make(UID, SHE_SECRET_KEY, SHE_MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, 1, &NO_FLAGS);
    expect(&emu, &m, SHE_ERC_KEY_INVALID);

    /* Empty authorizing slot. */
    she_emu_init(&emu, UID);
    m = spec_update(1, NEW_KEY);
    expect(&emu, &m, SHE_ERC_KEY_EMPTY);

    /* A key can authorize its own update. */
    new_she(&emu);
    m = spec_update(1, NEW_KEY);
    send_ok(&emu, &m);
    m = make(UID, SHE_KEY_1, SHE_KEY_1, NEW_KEY, ZERO_KEY, 2, &NO_FLAGS);
    send_ok(&emu, &m);

    /* RAM_KEY is loaded with SECRET_KEY. */
    she_emu_init(&emu, UID);
    she_emu_provision(&emu, SHE_SECRET_KEY, ALT_KEY, 0, NULL);
    m = make(UID, SHE_RAM_KEY, SHE_SECRET_KEY, ALT_KEY, NEW_KEY, 0, &NO_FLAGS);
    send_ok(&emu, &m);
    CHECK(memcmp(emu.slots[SHE_RAM_KEY].key, NEW_KEY, 16) == 0);

    /* Rotating MASTER_ECU_KEY: the old key stops working, the new one works. */
    new_she(&emu);
    m = make(UID, SHE_MASTER_ECU_KEY, SHE_MASTER_ECU_KEY, MASTER_KEY, ALT_KEY, 1, &NO_FLAGS);
    send_ok(&emu, &m);
    m = spec_update(1, NEW_KEY);
    expect(&emu, &m, SHE_ERC_KEY_UPDATE_ERROR);
    m = make(UID, SHE_KEY_1, SHE_MASTER_ECU_KEY, ALT_KEY, NEW_KEY, 1, &NO_FLAGS);
    send_ok(&emu, &m);

    /* BOOT_MAC can be updated with BOOT_MAC_KEY. */
    new_she(&emu);
    she_emu_provision(&emu, SHE_BOOT_MAC_KEY, ZERO_KEY, 0, NULL);
    m = make(UID, SHE_BOOT_MAC, SHE_BOOT_MAC_KEY, ZERO_KEY, NEW_KEY, 1, &NO_FLAGS);
    send_ok(&emu, &m);
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        void (*fn)(void);
    } groups[] = {{"crypto", test_crypto}, {"protocol", test_protocol}, {"emulator", test_emulator}};
    size_t i;
    int ran = 0;

    init_fixtures();
    for (i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        if (argc < 2 || strcmp(argv[1], groups[i].name) == 0) {
            groups[i].fn();
            ran++;
        }
    }
    if (!ran) {
        printf("unknown test group: %s\n", argv[1]);
        return 2;
    }
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
