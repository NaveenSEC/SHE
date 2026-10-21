/*
 * SHE CMD_LOAD_KEY memory update protocol (M1..M5) and a SHE module emulator.
 *
 * See docs/PROTOCOL.md for a step-by-step explanation with worked values.
 *
 * Message layout (SHE 1.1, 5-bit flag field):
 *
 *   M1 = UID(120) | ID(4) | AuthID(4)
 *   M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new(128) )
 *   M3 = CMAC,K2( M1 | M2 )
 *   M4 = UID(120) | ID(4) | AuthID(4) | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )
 *   M5 = CMAC,K4( M4 )
 *
 *   K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)    K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C)
 *   K3 = KDF(KEY_new, KEY_UPDATE_ENC_C)     K4 = KDF(KEY_new, KEY_UPDATE_MAC_C)
 */
#ifndef SHE_H
#define SHE_H

#include <stdbool.h>
#include <stdint.h>

#include "she_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHE_UID_SIZE 15u
#define SHE_KEY_SIZE 16u
#define SHE_MAX_COUNTER 0x0FFFFFFFu
#define SHE_NUM_SLOTS 15u

typedef enum {
    SHE_SECRET_KEY = 0x0,
    SHE_MASTER_ECU_KEY = 0x1,
    SHE_BOOT_MAC_KEY = 0x2,
    SHE_BOOT_MAC = 0x3,
    SHE_KEY_1 = 0x4,
    SHE_KEY_2 = 0x5,
    SHE_KEY_3 = 0x6,
    SHE_KEY_4 = 0x7,
    SHE_KEY_5 = 0x8,
    SHE_KEY_6 = 0x9,
    SHE_KEY_7 = 0xA,
    SHE_KEY_8 = 0xB,
    SHE_KEY_9 = 0xC,
    SHE_KEY_10 = 0xD,
    SHE_RAM_KEY = 0xE
} she_slot_t;

typedef enum {
    SHE_OK = 0,
    SHE_ERC_KEY_INVALID,
    SHE_ERC_KEY_EMPTY,
    SHE_ERC_KEY_WRITE_PROTECTED,
    SHE_ERC_KEY_UPDATE_ERROR,
    SHE_ERR_PARAM /* bad argument to this library, not a SHE error code */
} she_status_t;

typedef struct {
    bool write_protection;
    bool boot_protection;
    bool debugger_protection;
    bool key_usage;
    bool wildcard;
} she_flags_t;

typedef struct {
    uint8_t m1[16];
    uint8_t m2[32];
    uint8_t m3[16];
    uint8_t m4[32];
    uint8_t m5[16];
} she_messages_t;

typedef struct {
    uint32_t counter;
    she_flags_t flags;
    uint8_t key[SHE_KEY_SIZE];
} she_m2_plain_t;

const char *she_status_name(she_status_t status);
const char *she_slot_name(int slot);

/* F_ID packing: write protection is the MSB of the 5-bit field. */
uint8_t she_flags_to_bits(const she_flags_t *flags);
she_flags_t she_flags_from_bits(uint8_t bits);

/* ---- Host side --------------------------------------------------------- */

/* Build the M1..M3 request and the expected M4, M5 response. */
she_status_t she_build_key_update(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id,
                                  const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t new_key[SHE_KEY_SIZE],
                                  uint32_t counter, const she_flags_t *flags, she_messages_t *out);

void she_build_m1(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, uint8_t m1[16]);
void she_build_m3(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m1[16], const uint8_t m2[32],
                  uint8_t m3[16]);
void she_build_m4(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t new_key[SHE_KEY_SIZE],
                  uint32_t counter, uint8_t m4[32]);
void she_build_m5(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint8_t m5[16]);

void she_parse_m1(const uint8_t m1[16], uint8_t uid[SHE_UID_SIZE], int *key_id, int *auth_id);
void she_decode_m2(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m2[32], she_m2_plain_t *out);
/* Returns SHE_ERR_PARAM if the decrypted counter block is malformed (wrong key). */
she_status_t she_decode_m4_counter(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint32_t *counter);

/* Constant-time check that the module's M4, M5 match the expected ones. */
bool she_verify_response(const she_messages_t *expected, const uint8_t m4[32], const uint8_t m5[16]);

/* ---- Emulator ---------------------------------------------------------- */

typedef struct {
    bool present;
    uint8_t key[SHE_KEY_SIZE];
    uint32_t counter;
    she_flags_t flags;
} she_key_entry_t;

typedef struct {
    uint8_t uid[SHE_UID_SIZE];
    she_key_entry_t slots[SHE_NUM_SLOTS];
} she_emulator_t;

void she_emu_init(she_emulator_t *emu, const uint8_t uid[SHE_UID_SIZE]);
/* Factory-provision a slot directly (bypasses the update protocol). */
void she_emu_provision(she_emulator_t *emu, int slot, const uint8_t key[SHE_KEY_SIZE], uint32_t counter,
                       const she_flags_t *flags);
/* Process CMD_LOAD_KEY. On SHE_OK, m4 and m5 hold the response. */
she_status_t she_emu_load_key(she_emulator_t *emu, const uint8_t m1[16], const uint8_t m2[32],
                              const uint8_t m3[16], uint8_t m4[32], uint8_t m5[16]);

#ifdef __cplusplus
}
#endif

#endif /* SHE_H */
