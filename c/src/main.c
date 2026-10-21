/* she-update: build SHE CMD_LOAD_KEY messages M1..M5 and verify them against the emulator. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "she.h"

static void usage(const char *prog)
{
    printf("usage: %s [options]\n"
           "  --uid HEX             15-byte UID (default 00..01)\n"
           "  --key-id SLOT         slot to update, e.g. KEY_1 or 0x4 (default KEY_1)\n"
           "  --auth-id SLOT        authorizing slot (default MASTER_ECU_KEY)\n"
           "  --auth-key HEX        authorizing key (default 000102..0f)\n"
           "  --new-key HEX         new key (default 0f0e..00)\n"
           "  --counter N           new 28-bit counter (default 1)\n"
           "  --write-protection --boot-protection --debugger-protection --key-usage --wildcard\n"
           "  --no-emulate          only print the messages for a real ECU\n"
           "  --explain             show the derived keys and how each message is formed\n",
           prog);
}

static int parse_hex(const char *text, uint8_t *out, size_t size)
{
    size_t n = 0;
    while (*text) {
        unsigned value;
        if (isspace((unsigned char)*text)) {
            text++;
            continue;
        }
        if (n == size || !isxdigit((unsigned char)text[0]) || !isxdigit((unsigned char)text[1]) ||
            sscanf(text, "%2x", &value) != 1) {
            return 0;
        }
        out[n++] = (uint8_t)value;
        text += 2;
    }
    return n == size;
}

static int parse_slot(const char *text)
{
    char *end;
    long value;
    int i;
    for (i = 0; i < (int)SHE_NUM_SLOTS; i++) {
        const char *name = she_slot_name(i);
        size_t j = 0;
        while (name[j] && toupper((unsigned char)text[j]) == name[j]) {
            j++;
        }
        if (!name[j] && !text[j]) {
            return i;
        }
    }
    value = strtol(text, &end, 0);
    return (*end || value < 0 || value >= (long)SHE_NUM_SLOTS) ? -1 : (int)value;
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    printf("  %s ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_key(const char *label, const uint8_t key[16], const uint8_t constant[16])
{
    uint8_t derived[16];
    she_kdf(key, constant, derived);
    print_hex(label, derived, sizeof derived);
}

/* Print every intermediate value used to form M1..M5 (see docs/PROTOCOL.md). */
static void explain(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t auth_key[16],
                    const uint8_t new_key[16], uint32_t counter, const she_flags_t *flags, const she_messages_t *msgs)
{
    uint8_t f_id = she_flags_to_bits(flags);
    uint8_t m2_block1[16] = {0}, m4_block[16] = {0};
    int bit;

    /* C_ID(28) | F_ID(5) | 0(95) and C_ID(28) | 1 | 0(99), as built in she_protocol.c */
    m2_block1[0] = m4_block[0] = (uint8_t)(counter >> 20);
    m2_block1[1] = m4_block[1] = (uint8_t)(counter >> 12);
    m2_block1[2] = m4_block[2] = (uint8_t)(counter >> 4);
    m2_block1[3] = (uint8_t)((counter << 4) | (uint32_t)(f_id >> 1));
    m2_block1[4] = (uint8_t)((f_id & 1u) << 7);
    m4_block[3] = (uint8_t)((counter << 4) | 0x8u);

    printf("Inputs:\n");
    print_hex("UID     ", uid, SHE_UID_SIZE);
    printf("  ID       0x%x (%s)\n", key_id, she_slot_name(key_id));
    printf("  AuthID   0x%x (%s)\n", auth_id, she_slot_name(auth_id));
    print_hex("K_AuthID", auth_key, 16);
    print_hex("KEY_new ", new_key, 16);
    printf("  C_ID     0x%lx\n", (unsigned long)counter);
    printf("  F_ID     ");
    for (bit = 4; bit >= 0; bit--) {
        putchar((f_id >> bit) & 1u ? '1' : '0');
    }
    printf(" (WP BP DP KU WC)\n");

    printf("Derived keys, KDF(K, C) = Miyaguchi-Preneel(K | C):\n");
    print_key("K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) =", auth_key, SHE_KEY_UPDATE_ENC_C);
    print_key("K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) =", auth_key, SHE_KEY_UPDATE_MAC_C);
    print_key("K3 = KDF(KEY_new,  KEY_UPDATE_ENC_C) =", new_key, SHE_KEY_UPDATE_ENC_C);
    print_key("K4 = KDF(KEY_new,  KEY_UPDATE_MAC_C) =", new_key, SHE_KEY_UPDATE_MAC_C);

    printf("Message formation:\n");
    printf("  M1 = UID | ID | AuthID\n");
    printf("     last byte = (ID << 4) | AuthID = %02x\n", msgs->m1[15]);
    printf("  M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new )\n");
    print_hex("   plaintext block 1 =", m2_block1, 16);
    print_hex("   plaintext block 2 =", new_key, 16);
    printf("  M3 = CMAC,K2( M1 | M2 )\n");
    printf("  M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )\n");
    print_hex("   counter block     =", m4_block, 16);
    print_hex("   encrypted block   =", &msgs->m4[16], 16);
    printf("  M5 = CMAC,K4( M4 )\n\n");
}

int main(int argc, char **argv)
{
    uint8_t uid[SHE_UID_SIZE] = {0};
    uint8_t auth_key[SHE_KEY_SIZE], new_key[SHE_KEY_SIZE];
    int key_id = SHE_KEY_1, auth_id = SHE_MASTER_ECU_KEY, emulate = 1, show_explain = 0, i;
    unsigned long counter = 1;
    she_flags_t flags = {false, false, false, false, false};
    she_messages_t msgs;
    she_emulator_t emu;
    she_status_t status;
    uint8_t m4[32], m5[16];

    uid[SHE_UID_SIZE - 1] = 0x01;
    for (i = 0; i < (int)SHE_KEY_SIZE; i++) {
        auth_key[i] = (uint8_t)i;
        new_key[i] = (uint8_t)(15 - i);
    }

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *val = (i + 1 < argc) ? argv[i + 1] : NULL;
        int ok = 1;
        if (!strcmp(arg, "--help") || !strcmp(arg, "-h")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(arg, "--write-protection")) {
            flags.write_protection = true;
        } else if (!strcmp(arg, "--boot-protection")) {
            flags.boot_protection = true;
        } else if (!strcmp(arg, "--debugger-protection")) {
            flags.debugger_protection = true;
        } else if (!strcmp(arg, "--key-usage")) {
            flags.key_usage = true;
        } else if (!strcmp(arg, "--wildcard")) {
            flags.wildcard = true;
        } else if (!strcmp(arg, "--no-emulate")) {
            emulate = 0;
        } else if (!strcmp(arg, "--explain")) {
            show_explain = 1;
        } else if (val == NULL) {
            ok = 0;
        } else {
            i++;
            if (!strcmp(arg, "--uid")) {
                ok = parse_hex(val, uid, sizeof uid);
            } else if (!strcmp(arg, "--auth-key")) {
                ok = parse_hex(val, auth_key, sizeof auth_key);
            } else if (!strcmp(arg, "--new-key")) {
                ok = parse_hex(val, new_key, sizeof new_key);
            } else if (!strcmp(arg, "--key-id")) {
                ok = (key_id = parse_slot(val)) >= 0;
            } else if (!strcmp(arg, "--auth-id")) {
                ok = (auth_id = parse_slot(val)) >= 0;
            } else if (!strcmp(arg, "--counter")) {
                char *end;
                counter = strtoul(val, &end, 0);
                ok = !*end && counter <= SHE_MAX_COUNTER;
            } else {
                ok = 0;
            }
        }
        if (!ok) {
            fprintf(stderr, "invalid argument: %s%s%s\n", arg, val ? " " : "", val ? val : "");
            usage(argv[0]);
            return 2;
        }
    }

    status = she_build_key_update(uid, key_id, auth_id, auth_key, new_key, (uint32_t)counter, &flags, &msgs);
    if (status != SHE_OK) {
        fprintf(stderr, "cannot build messages: %s\n", she_status_name(status));
        return 2;
    }

    if (show_explain) {
        explain(uid, key_id, auth_id, auth_key, new_key, (uint32_t)counter, &flags, &msgs);
    }

    printf("Request (send to the SHE module):\n");
    print_hex("M1", msgs.m1, sizeof msgs.m1);
    print_hex("M2", msgs.m2, sizeof msgs.m2);
    print_hex("M3", msgs.m3, sizeof msgs.m3);
    printf("Expected response:\n");
    print_hex("M4", msgs.m4, sizeof msgs.m4);
    print_hex("M5", msgs.m5, sizeof msgs.m5);

    if (!emulate) {
        return 0;
    }

    she_emu_init(&emu, uid);
    she_emu_provision(&emu, auth_id, auth_key, 0, NULL);
    status = she_emu_load_key(&emu, msgs.m1, msgs.m2, msgs.m3, m4, m5);
    if (status != SHE_OK) {
        printf("Emulator rejected the request: %s\n", she_status_name(status));
        return 1;
    }
    if (!she_verify_response(&msgs, m4, m5)) {
        printf("Emulator response MISMATCH\n");
        return 1;
    }
    printf("Emulator response verified: key stored in %s\n", she_slot_name(key_id));
    return 0;
}
