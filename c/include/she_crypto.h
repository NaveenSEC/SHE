/*
 * SHE cryptographic primitives: AES-128 ECB/CBC, AES-CMAC and the
 * Miyaguchi-Preneel key derivation function.
 *
 * Self-contained C99 with no external dependencies, so it can be built for
 * a host PC or dropped into microcontroller firmware.
 */
#ifndef SHE_CRYPTO_H
#define SHE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHE_BLOCK_SIZE 16u

/* KDF constants from the SHE specification. */
extern const uint8_t SHE_KEY_UPDATE_ENC_C[SHE_BLOCK_SIZE];
extern const uint8_t SHE_KEY_UPDATE_MAC_C[SHE_BLOCK_SIZE];

void she_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void she_aes128_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* len must be a multiple of 16. in and out may be the same buffer. */
void she_ecb_encrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len);
void she_ecb_decrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t len);
void she_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);
void she_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);

/* AES-CMAC (NIST SP 800-38B / RFC 4493). */
void she_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]);

/*
 * Miyaguchi-Preneel compression: H_i = E_{H_{i-1}}(x_i) ^ x_i ^ H_{i-1}, H_0 = 0.
 * With pad != 0 the SHE padding (1 bit, zeros, 40-bit length) is applied and
 * len may be any value; without padding len must be a multiple of 16.
 */
void she_miyaguchi_preneel(const uint8_t *msg, size_t len, int pad, uint8_t out[16]);

/* SHE KDF(K, C) = MP(K || C). */
void she_kdf(const uint8_t key[16], const uint8_t constant[16], uint8_t out[16]);

/* Returns 1 if equal. Runs in time independent of where the buffers differ. */
int she_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SHE_CRYPTO_H */
