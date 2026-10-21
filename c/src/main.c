/* she-update: build SHE CMD_LOAD_KEY messages M1..M5 and verify them against the emulator. */
#include <ctype.h>  /* isspace, isxdigit, toupper */
#include <stdio.h>  /* printf, fprintf, sscanf */
#include <stdlib.h> /* strtol, strtoul */
#include <string.h> /* strcmp */

#include "she.h"    /* protocol, crypto and emulator API */

/* Print the command line help. */
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

/* Parse exactly `size` bytes of hex ("0011aa" or "00 11 aa") into out. Returns 1 on success. */
static int parse_hex(const char *text, uint8_t *out, size_t size)
{
    size_t n = 0;                          /* bytes written so far */
    while (*text) {
        unsigned value;
        if (isspace((unsigned char)*text)) {
            text++;                        /* skip spaces between bytes */
            continue;
        }
        /* Need room for another byte and two hex digits. */
        if (n == size || !isxdigit((unsigned char)text[0]) || !isxdigit((unsigned char)text[1]) ||
            sscanf(text, "%2x", &value) != 1) {
            return 0;                      /* too long or not hex */
        }
        out[n++] = (uint8_t)value;         /* store one byte */
        text += 2;                         /* advance past the two digits */
    }
    return n == size;                      /* must be exactly the right length */
}

/* Parse a slot given by name (KEY_1, ram_key) or number (4, 0x4). Returns -1 if invalid. */
static int parse_slot(const char *text)
{
    char *end;
    long value;
    int i;
    for (i = 0; i < (int)SHE_NUM_SLOTS; i++) {   /* try every slot name */
        const char *name = she_slot_name(i);
        size_t j = 0;
        while (name[j] && toupper((unsigned char)text[j]) == name[j]) {
            j++;                                   /* case-insensitive compare */
        }
        if (!name[j] && !text[j]) {
            return i;                              /* whole name matched */
        }
    }
    value = strtol(text, &end, 0);                 /* base 0: accepts 4, 0x4, 04 */
    return (*end || value < 0 || value >= (long)SHE_NUM_SLOTS) ? -1 : (int)value; /* reject junk / out of range */
}

/* Print "  label 0011aa..." */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    printf("  %s ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]); /* two lowercase hex digits per byte */
    }
    printf("\n");
}

/* Print KDF(key, constant) with a label. */
static void print_key(const char *label, const uint8_t key[16], const uint8_t constant[16])
{
    uint8_t derived[16];
    she_kdf(key, constant, derived);              /* derived = MP(key | constant) */
    print_hex(label, derived, sizeof derived);
}

/* Print every intermediate value used to form M1..M5 (see docs/PROTOCOL.md). */
static void explain(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t auth_key[16],
                    const uint8_t new_key[16], uint32_t counter, const she_flags_t *flags, const she_messages_t *msgs)
{
    uint8_t f_id = she_flags_to_bits(flags);         /* F_ID = WP<<4 | BP<<3 | DP<<2 | KU<<1 | WC */
    uint8_t m2_block1[16] = {0}, m4_block[16] = {0}; /* zero-filled plaintext blocks */
    int bit;

    /* C_ID(28) | F_ID(5) | 0(95) and C_ID(28) | 1 | 0(99), as built in she_protocol.c */
    m2_block1[0] = m4_block[0] = (uint8_t)(counter >> 20);           /* C_ID bits 27..20 */
    m2_block1[1] = m4_block[1] = (uint8_t)(counter >> 12);           /* C_ID bits 19..12 */
    m2_block1[2] = m4_block[2] = (uint8_t)(counter >> 4);            /* C_ID bits 11..4 */
    m2_block1[3] = (uint8_t)((counter << 4) | (uint32_t)(f_id >> 1)); /* C_ID bits 3..0 | F_ID bits 4..1 */
    m2_block1[4] = (uint8_t)((f_id & 1u) << 7);                       /* F_ID bit 0, then zeros */
    m4_block[3] = (uint8_t)((counter << 4) | 0x8u);                   /* C_ID bits 3..0 | the single 1 bit */

    printf("Inputs:\n");
    print_hex("UID     ", uid, SHE_UID_SIZE);                                   /* 120-bit module UID */
    printf("  ID       0x%x (%s)\n", key_id, she_slot_name(key_id));            /* slot to write */
    printf("  AuthID   0x%x (%s)\n", auth_id, she_slot_name(auth_id));          /* authorizing slot */
    print_hex("K_AuthID", auth_key, 16);                                        /* authorizing key */
    print_hex("KEY_new ", new_key, 16);                                         /* new key */
    printf("  C_ID     0x%lx\n", (unsigned long)counter);                       /* 28-bit counter */
    printf("  F_ID     ");
    for (bit = 4; bit >= 0; bit--) {
        putchar((f_id >> bit) & 1u ? '1' : '0');                                /* flags as 5 binary digits */
    }
    printf(" (WP BP DP KU WC)\n");

    printf("Derived keys, KDF(K, C) = Miyaguchi-Preneel(K | C):\n");
    print_key("K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) =", auth_key, SHE_KEY_UPDATE_ENC_C); /* encrypts M2 */
    print_key("K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) =", auth_key, SHE_KEY_UPDATE_MAC_C); /* MAC key for M3 */
    print_key("K3 = KDF(KEY_new,  KEY_UPDATE_ENC_C) =", new_key, SHE_KEY_UPDATE_ENC_C);  /* encrypts M4 block */
    print_key("K4 = KDF(KEY_new,  KEY_UPDATE_MAC_C) =", new_key, SHE_KEY_UPDATE_MAC_C);  /* MAC key for M5 */

    printf("Message formation:\n");
    printf("  M1 = UID | ID | AuthID\n");
    printf("     last byte = (ID << 4) | AuthID = %02x\n", msgs->m1[15]);
    printf("  M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new )\n");
    print_hex("   plaintext block 1 =", m2_block1, 16);     /* counter + flags */
    print_hex("   plaintext block 2 =", new_key, 16);       /* the new key */
    printf("  M3 = CMAC,K2( M1 | M2 )\n");
    printf("  M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )\n");
    print_hex("   counter block     =", m4_block, 16);      /* before encryption */
    print_hex("   encrypted block   =", &msgs->m4[16], 16); /* E_K3(counter block) */
    printf("  M5 = CMAC,K4( M4 )\n\n");
}

int main(int argc, char **argv)
{
    uint8_t uid[SHE_UID_SIZE] = {0};                  /* UID, default 00..01 */
    uint8_t auth_key[SHE_KEY_SIZE], new_key[SHE_KEY_SIZE];
    int key_id = SHE_KEY_1, auth_id = SHE_MASTER_ECU_KEY, emulate = 1, show_explain = 0, i;
    unsigned long counter = 1;                        /* C_ID, default 1 */
    she_flags_t flags = {false, false, false, false, false}; /* F_ID, default none */
    she_messages_t msgs;                              /* M1..M5 computed by the host */
    she_emulator_t emu;                               /* emulated SHE module */
    she_status_t status;
    uint8_t m4[32], m5[16];                           /* response from the emulator */

    /* Defaults = SHE specification example. */
    uid[SHE_UID_SIZE - 1] = 0x01;                     /* UID = 000...01 */
    for (i = 0; i < (int)SHE_KEY_SIZE; i++) {
        auth_key[i] = (uint8_t)i;                     /* K_AuthID = 000102..0f */
        new_key[i] = (uint8_t)(15 - i);               /* KEY_new  = 0f0e..00 */
    }

    for (i = 1; i < argc; i++) {                      /* walk the command line options */
        const char *arg = argv[i];
        const char *val = (i + 1 < argc) ? argv[i + 1] : NULL; /* next word, if any, is the option's value */
        int ok = 1;
        if (!strcmp(arg, "--help") || !strcmp(arg, "-h")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(arg, "--write-protection")) {
            flags.write_protection = true;            /* F_ID bit 4 */
        } else if (!strcmp(arg, "--boot-protection")) {
            flags.boot_protection = true;             /* F_ID bit 3 */
        } else if (!strcmp(arg, "--debugger-protection")) {
            flags.debugger_protection = true;         /* F_ID bit 2 */
        } else if (!strcmp(arg, "--key-usage")) {
            flags.key_usage = true;                   /* F_ID bit 1 */
        } else if (!strcmp(arg, "--wildcard")) {
            flags.wildcard = true;                    /* F_ID bit 0 */
        } else if (!strcmp(arg, "--no-emulate")) {
            emulate = 0;                              /* real-ECU mode */
        } else if (!strcmp(arg, "--explain")) {
            show_explain = 1;                         /* print intermediate values */
        } else if (val == NULL) {
            ok = 0;                                   /* option needs a value but none follows */
        } else {
            i++;                                      /* consume the value */
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
                counter = strtoul(val, &end, 0);      /* decimal or 0x.. */
                ok = !*end && counter <= SHE_MAX_COUNTER; /* whole string parsed, fits in 28 bits */
            } else {
                ok = 0;                               /* unknown option */
            }
        }
        if (!ok) {
            fprintf(stderr, "invalid argument: %s%s%s\n", arg, val ? " " : "", val ? val : "");
            usage(argv[0]);
            return 2;                                 /* exit code 2 = usage error */
        }
    }

    /* Host side: compute the request M1..M3 and the expected answer M4, M5. */
    status = she_build_key_update(uid, key_id, auth_id, auth_key, new_key, (uint32_t)counter, &flags, &msgs);
    if (status != SHE_OK) {
        fprintf(stderr, "cannot build messages: %s\n", she_status_name(status));
        return 2;
    }

    if (show_explain) {
        explain(uid, key_id, auth_id, auth_key, new_key, (uint32_t)counter, &flags, &msgs);
    }

    printf("Request (send to the SHE module):\n");
    print_hex("M1", msgs.m1, sizeof msgs.m1);         /* 16 bytes */
    print_hex("M2", msgs.m2, sizeof msgs.m2);         /* 32 bytes */
    print_hex("M3", msgs.m3, sizeof msgs.m3);         /* 16 bytes */
    printf("Expected response:\n");
    print_hex("M4", msgs.m4, sizeof msgs.m4);         /* 32 bytes */
    print_hex("M5", msgs.m5, sizeof msgs.m5);         /* 16 bytes */

    if (!emulate) {
        return 0;                                     /* real-ECU mode stops here */
    }

    she_emu_init(&emu, uid);                          /* emulated module with the same UID */
    she_emu_provision(&emu, auth_id, auth_key, 0, NULL); /* pre-load K_AuthID into slot AuthID */
    status = she_emu_load_key(&emu, msgs.m1, msgs.m2, msgs.m3, m4, m5); /* send the request */
    if (status != SHE_OK) {
        printf("Emulator rejected the request: %s\n", she_status_name(status));
        return 1;
    }
    if (!she_verify_response(&msgs, m4, m5)) {        /* module's M4, M5 must match the host's */
        printf("Emulator response MISMATCH\n");
        return 1;
    }
    printf("Emulator response verified: key stored in %s\n", she_slot_name(key_id));
    return 0;                                         /* key confirmed stored */
}
