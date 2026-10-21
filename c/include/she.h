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

#include <stdbool.h> /* bool */
#include <stdint.h>  /* uint8_t, uint32_t */

#include "she_crypto.h" /* AES, CMAC, KDF */

#ifdef __cplusplus
extern "C" { /* C linkage so the library can be called from C++ */
#endif

#define SHE_UID_SIZE 15u            /* UID is 120 bits = 15 bytes */
#define SHE_KEY_SIZE 16u            /* AES-128 keys are 16 bytes */
#define SHE_MAX_COUNTER 0x0FFFFFFFu /* C_ID is 28 bits: largest value 2^28 - 1 */
#define SHE_NUM_SLOTS 15u           /* slot IDs 0x0..0xE */

/* Key slot IDs: the 4-bit ID / AuthID values used in M1 and M4. */
typedef enum {
    SHE_SECRET_KEY = 0x0,     /* factory secret; can never be loaded via CMD_LOAD_KEY */
    SHE_MASTER_ECU_KEY = 0x1, /* master key: may authorize updates of every slot except SECRET_KEY */
    SHE_BOOT_MAC_KEY = 0x2,   /* key used to compute the secure-boot MAC */
    SHE_BOOT_MAC = 0x3,       /* stored reference MAC of the bootloader */
    SHE_KEY_1 = 0x4,          /* general purpose keys KEY_1 .. KEY_10 */
    SHE_KEY_2 = 0x5,
    SHE_KEY_3 = 0x6,
    SHE_KEY_4 = 0x7,
    SHE_KEY_5 = 0x8,
    SHE_KEY_6 = 0x9,
    SHE_KEY_7 = 0xA,
    SHE_KEY_8 = 0xB,
    SHE_KEY_9 = 0xC,
    SHE_KEY_10 = 0xD,
    SHE_RAM_KEY = 0xE         /* volatile key; loaded with SECRET_KEY, no counter or flags */
} she_slot_t;

/* Result codes. The ERC_ values are the SHE error codes a real module returns. */
typedef enum {
    SHE_OK = 0,                  /* success: M4, M5 are valid */
    SHE_ERC_KEY_INVALID,         /* slot cannot be written, or AuthID may not write it */
    SHE_ERC_KEY_EMPTY,           /* authorizing slot holds no key */
    SHE_ERC_KEY_WRITE_PROTECTED, /* target slot has WRITE_PROTECTION set */
    SHE_ERC_KEY_UPDATE_ERROR,    /* bad M3, wrong UID or counter not increasing */
    SHE_ERR_PARAM /* bad argument to this library, not a SHE error code */
} she_status_t;

/* The 5 protection flags F_ID stored with a key (SHE 1.1). */
typedef struct {
    bool write_protection;    /* WP, F_ID bit 4: slot can never be updated again */
    bool boot_protection;     /* BP, F_ID bit 3: key unusable if secure boot failed */
    bool debugger_protection; /* DP, F_ID bit 2: key unusable while a debugger is attached */
    bool key_usage;           /* KU, F_ID bit 1: 0 = encryption key, 1 = MAC key */
    bool wildcard;            /* WC, F_ID bit 0: later updates may use the wildcard UID */
} she_flags_t;

/* The five messages of one key update. */
typedef struct {
    uint8_t m1[16]; /* UID | ID | AuthID                          (host -> module) */
    uint8_t m2[32]; /* ENC_CBC,K1(C_ID | F_ID | 0 | KEY_new)       (host -> module) */
    uint8_t m3[16]; /* CMAC,K2(M1 | M2)                            (host -> module) */
    uint8_t m4[32]; /* UID | ID | AuthID | ENC_ECB,K3(C_ID | 1 | 0) (module -> host) */
    uint8_t m5[16]; /* CMAC,K4(M4)                                 (module -> host) */
} she_messages_t;

/* The plaintext fields carried inside M2. */
typedef struct {
    uint32_t counter;          /* C_ID, 28 bits */
    she_flags_t flags;         /* F_ID, 5 bits */
    uint8_t key[SHE_KEY_SIZE]; /* KEY_new */
} she_m2_plain_t;

const char *she_status_name(she_status_t status); /* "ERC_KEY_EMPTY" etc. */
const char *she_slot_name(int slot);              /* "KEY_1" etc., "INVALID" if out of range */

/* F_ID packing: write protection is the MSB of the 5-bit field. */
uint8_t she_flags_to_bits(const she_flags_t *flags); /* F_ID = WP<<4 | BP<<3 | DP<<2 | KU<<1 | WC */
she_flags_t she_flags_from_bits(uint8_t bits);       /* inverse of she_flags_to_bits */

/* ---- Host side --------------------------------------------------------- */

/* Build the M1..M3 request and the expected M4, M5 response. flags may be NULL (no flags). */
she_status_t she_build_key_update(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id,
                                  const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t new_key[SHE_KEY_SIZE],
                                  uint32_t counter, const she_flags_t *flags, she_messages_t *out);

/* M1 = UID(120) | ID(4) | AuthID(4) */
void she_build_m1(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, uint8_t m1[16]);
/* M3 = CMAC,K2(M1 | M2), K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) */
void she_build_m3(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m1[16], const uint8_t m2[32],
                  uint8_t m3[16]);
/* M4 = UID | ID | AuthID | ENC_ECB,K3(C_ID(28) | 1 | 0(99)), K3 = KDF(KEY_new, KEY_UPDATE_ENC_C) */
void she_build_m4(const uint8_t uid[SHE_UID_SIZE], int key_id, int auth_id, const uint8_t new_key[SHE_KEY_SIZE],
                  uint32_t counter, uint8_t m4[32]);
/* M5 = CMAC,K4(M4), K4 = KDF(KEY_new, KEY_UPDATE_MAC_C) */
void she_build_m5(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint8_t m5[16]);

/* Split M1 into UID (bytes 0..14), ID (byte 15 high nibble), AuthID (byte 15 low nibble). */
void she_parse_m1(const uint8_t m1[16], uint8_t uid[SHE_UID_SIZE], int *key_id, int *auth_id);
/* Decrypt M2 with K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) into C_ID, F_ID, KEY_new. */
void she_decode_m2(const uint8_t auth_key[SHE_KEY_SIZE], const uint8_t m2[32], she_m2_plain_t *out);
/* Returns SHE_ERR_PARAM if the decrypted counter block is malformed (wrong key). */
she_status_t she_decode_m4_counter(const uint8_t new_key[SHE_KEY_SIZE], const uint8_t m4[32], uint32_t *counter);

/* Constant-time check that the module's M4, M5 match the expected ones. */
bool she_verify_response(const she_messages_t *expected, const uint8_t m4[32], const uint8_t m5[16]);

/* ---- Emulator ---------------------------------------------------------- */

/* One key slot of the emulated module's memory. */
typedef struct {
    bool present;              /* false = slot empty */
    uint8_t key[SHE_KEY_SIZE]; /* key value */
    uint32_t counter;          /* C_ID of the last successful update */
    she_flags_t flags;         /* F_ID of the last successful update */
} she_key_entry_t;

/* The emulated SHE module. */
typedef struct {
    uint8_t uid[SHE_UID_SIZE];            /* this module's UID */
    she_key_entry_t slots[SHE_NUM_SLOTS]; /* indexed by slot ID */
} she_emulator_t;

/* Initialise with a UID and all slots empty. */
void she_emu_init(she_emulator_t *emu, const uint8_t uid[SHE_UID_SIZE]);
/* Factory-provision a slot directly (bypasses the update protocol). flags may be NULL. */
void she_emu_provision(she_emulator_t *emu, int slot, const uint8_t key[SHE_KEY_SIZE], uint32_t counter,
                       const she_flags_t *flags);
/* Process CMD_LOAD_KEY. On SHE_OK, m4 and m5 hold the response. */
she_status_t she_emu_load_key(she_emulator_t *emu, const uint8_t m1[16], const uint8_t m2[32],
                              const uint8_t m3[16], uint8_t m4[32], uint8_t m5[16]);

#ifdef __cplusplus
}
#endif

#endif /* SHE_H */
