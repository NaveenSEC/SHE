/* A software SHE module that processes CMD_LOAD_KEY the way the hardware does. */
#include <string.h>

#include "she.h"

static const uint8_t WILDCARD_UID[SHE_UID_SIZE] = {0};

void she_emu_init(she_emulator_t *emu, const uint8_t uid[SHE_UID_SIZE])
{
    memset(emu, 0, sizeof *emu);
    memcpy(emu->uid, uid, SHE_UID_SIZE);
}

void she_emu_provision(she_emulator_t *emu, int slot, const uint8_t key[SHE_KEY_SIZE], uint32_t counter,
                       const she_flags_t *flags)
{
    she_key_entry_t *e = &emu->slots[slot];
    e->present = true;
    memcpy(e->key, key, SHE_KEY_SIZE);
    e->counter = counter;
    memset(&e->flags, 0, sizeof e->flags);
    if (flags) {
        e->flags = *flags;
    }
}

/* Which slots may authorize an update of key_id (SHE spec, CMD_LOAD_KEY). */
static bool auth_allowed(int key_id, int auth_id)
{
    if (key_id == SHE_RAM_KEY) {
        return auth_id == SHE_SECRET_KEY;
    }
    if (key_id == SHE_BOOT_MAC) {
        return auth_id == SHE_MASTER_ECU_KEY || auth_id == SHE_BOOT_MAC_KEY;
    }
    /* MASTER_ECU_KEY, BOOT_MAC_KEY and KEY_1..KEY_10: the master key or the key itself. */
    return auth_id == SHE_MASTER_ECU_KEY || auth_id == key_id;
}

she_status_t she_emu_load_key(she_emulator_t *emu, const uint8_t m1[16], const uint8_t m2[32],
                              const uint8_t m3[16], uint8_t m4[32], uint8_t m5[16])
{
    uint8_t uid[SHE_UID_SIZE], expected_m3[16];
    int key_id, auth_id;
    const she_key_entry_t *auth;
    she_key_entry_t *current;
    she_m2_plain_t plain;
    uint32_t counter;
    she_flags_t flags;

    she_parse_m1(m1, uid, &key_id, &auth_id);

    if (key_id == SHE_SECRET_KEY || key_id > SHE_RAM_KEY || !auth_allowed(key_id, auth_id)) {
        return SHE_ERC_KEY_INVALID;
    }

    auth = &emu->slots[auth_id];
    if (!auth->present) {
        return SHE_ERC_KEY_EMPTY;
    }

    she_build_m3(auth->key, m1, m2, expected_m3);
    if (!she_ct_equal(expected_m3, m3, 16)) {
        return SHE_ERC_KEY_UPDATE_ERROR;
    }

    current = &emu->slots[key_id];
    if (memcmp(uid, emu->uid, SHE_UID_SIZE) != 0) {
        bool wildcard_ok = memcmp(uid, WILDCARD_UID, SHE_UID_SIZE) == 0 && current->present &&
                           current->flags.wildcard;
        if (!wildcard_ok) {
            return SHE_ERC_KEY_UPDATE_ERROR;
        }
    }

    if (current->present && current->flags.write_protection) {
        return SHE_ERC_KEY_WRITE_PROTECTED;
    }

    she_decode_m2(auth->key, m2, &plain);
    if (key_id == SHE_RAM_KEY) {
        /* RAM_KEY has no counter and no flags. */
        counter = 0;
        memset(&flags, 0, sizeof flags);
    } else {
        if (current->present && plain.counter <= current->counter) {
            return SHE_ERC_KEY_UPDATE_ERROR;
        }
        counter = plain.counter;
        flags = plain.flags;
    }

    she_emu_provision(emu, key_id, plain.key, counter, &flags);

    she_build_m4(emu->uid, key_id, auth_id, plain.key, counter, m4);
    she_build_m5(plain.key, m4, m5);
    return SHE_OK;
}
