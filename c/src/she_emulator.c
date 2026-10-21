/*
 * A software SHE module that processes CMD_LOAD_KEY the way the hardware does.
 *
 * Check order when M1, M2, M3 arrive (see docs/PROTOCOL.md section 9):
 *   1. slot rules (ID / AuthID)            -> ERC_KEY_INVALID
 *   2. authorizing key present             -> ERC_KEY_EMPTY
 *   3. M3 == CMAC,K2(M1 | M2)              -> ERC_KEY_UPDATE_ERROR
 *   4. UID matches (or wildcard allowed)   -> ERC_KEY_UPDATE_ERROR
 *   5. slot not write protected            -> ERC_KEY_WRITE_PROTECTED
 *   6. decrypt M2 with K1
 *   7. new counter > stored counter        -> ERC_KEY_UPDATE_ERROR
 *   8. store key, answer with M4, M5
 */
#include <string.h> /* memcpy, memset, memcmp */

#include "she.h"    /* public API */

static const uint8_t WILDCARD_UID[SHE_UID_SIZE] = {0}; /* all-zero UID = "any module" */

/* Start an emulator with the given UID and every slot empty. */
void she_emu_init(she_emulator_t *emu, const uint8_t uid[SHE_UID_SIZE])
{
    memset(emu, 0, sizeof *emu);            /* all slots: present = false */
    memcpy(emu->uid, uid, SHE_UID_SIZE);    /* this module's unique ID */
}

/* Write a slot directly, as the factory would (bypasses all protocol checks). */
void she_emu_provision(she_emulator_t *emu, int slot, const uint8_t key[SHE_KEY_SIZE], uint32_t counter,
                       const she_flags_t *flags)
{
    she_key_entry_t *e = &emu->slots[slot]; /* the slot to fill */
    e->present = true;                      /* slot now holds a key */
    memcpy(e->key, key, SHE_KEY_SIZE);      /* key value */
    e->counter = counter;                   /* C_ID */
    memset(&e->flags, 0, sizeof e->flags);  /* default: no flags */
    if (flags) {
        e->flags = *flags;                  /* F_ID if given */
    }
}

/* Which slots may authorize an update of key_id (SHE spec, CMD_LOAD_KEY). */
static bool auth_allowed(int key_id, int auth_id)
{
    if (key_id == SHE_RAM_KEY) {
        return auth_id == SHE_SECRET_KEY;   /* RAM_KEY is loaded with SECRET_KEY */
    }
    if (key_id == SHE_BOOT_MAC) {
        return auth_id == SHE_MASTER_ECU_KEY || auth_id == SHE_BOOT_MAC_KEY; /* master key or BOOT_MAC_KEY */
    }
    /* MASTER_ECU_KEY, BOOT_MAC_KEY and KEY_1..KEY_10: the master key or the key itself. */
    return auth_id == SHE_MASTER_ECU_KEY || auth_id == key_id;
}

she_status_t she_emu_load_key(she_emulator_t *emu, const uint8_t m1[16], const uint8_t m2[32],
                              const uint8_t m3[16], uint8_t m4[32], uint8_t m5[16])
{
    uint8_t uid[SHE_UID_SIZE], expected_m3[16]; /* UID from M1, and the M3 we compute ourselves */
    int key_id, auth_id;                        /* ID and AuthID from M1 */
    const she_key_entry_t *auth;                /* authorizing slot */
    she_key_entry_t *current;                   /* target slot */
    she_m2_plain_t plain;                       /* decrypted M2 */
    uint32_t counter;                           /* counter to store */
    she_flags_t flags;                          /* flags to store */

    she_parse_m1(m1, uid, &key_id, &auth_id);   /* M1 = UID | ID | AuthID */

    /* Step 1: SECRET_KEY (0x0) and 0xF can never be written; AuthID must be allowed for this slot. */
    if (key_id == SHE_SECRET_KEY || key_id > SHE_RAM_KEY || !auth_allowed(key_id, auth_id)) {
        return SHE_ERC_KEY_INVALID;
    }

    /* Step 2: the authorizing key K_AuthID must be present. */
    auth = &emu->slots[auth_id];
    if (!auth->present) {
        return SHE_ERC_KEY_EMPTY;
    }

    /* Step 3: authenticate the request: M3 must equal CMAC,K2(M1 | M2), K2 = KDF(K_AuthID, MAC_C). */
    she_build_m3(auth->key, m1, m2, expected_m3);
    if (!she_ct_equal(expected_m3, m3, 16)) {   /* constant-time comparison */
        return SHE_ERC_KEY_UPDATE_ERROR;        /* tampered message or wrong K_AuthID */
    }

    /* Step 4: the request must be for this module. */
    current = &emu->slots[key_id];
    if (memcmp(uid, emu->uid, SHE_UID_SIZE) != 0) { /* not our UID ... */
        /* ... only accepted if it is the wildcard UID AND the slot already has the WILDCARD flag. */
        bool wildcard_ok = memcmp(uid, WILDCARD_UID, SHE_UID_SIZE) == 0 && current->present &&
                           current->flags.wildcard;
        if (!wildcard_ok) {
            return SHE_ERC_KEY_UPDATE_ERROR;
        }
    }

    /* Step 5: a write-protected slot can never be changed again. */
    if (current->present && current->flags.write_protection) {
        return SHE_ERC_KEY_WRITE_PROTECTED;
    }

    /* Step 6: decrypt M2 with K1 = KDF(K_AuthID, ENC_C) -> C_ID, F_ID, KEY_new. */
    she_decode_m2(auth->key, m2, &plain);
    if (key_id == SHE_RAM_KEY) {
        /* RAM_KEY has no counter and no flags. */
        counter = 0;
        memset(&flags, 0, sizeof flags);
    } else {
        /* Step 7: anti-replay. The new counter must be strictly greater than the stored one. */
        if (current->present && plain.counter <= current->counter) {
            return SHE_ERC_KEY_UPDATE_ERROR;
        }
        counter = plain.counter;  /* accept the new C_ID */
        flags = plain.flags;      /* accept the new F_ID */
    }

    /* Step 8: store the key, then prove it with M4/M5 keyed by the NEW key. */
    she_emu_provision(emu, key_id, plain.key, counter, &flags);

    she_build_m4(emu->uid, key_id, auth_id, plain.key, counter, m4); /* always the module's real UID */
    she_build_m5(plain.key, m4, m5);                                  /* M5 = CMAC,K4(M4) */
    return SHE_OK;
}
