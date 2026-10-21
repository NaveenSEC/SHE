# How M1–M5 are formed

This document explains, step by step, how each message of the SHE `CMD_LOAD_KEY` (memory
update) protocol is built, with the formula for each one and the real intermediate values for
the SHE specification example. The code that implements each step is listed under each section
(Python file / C file).

- [1. Overview](#1-overview)
- [2. Building blocks](#2-building-blocks)
- [3. Key derivation: K1, K2, K3, K4](#3-key-derivation-k1-k2-k3-k4)
- [4. M1: who and which key](#4-m1-who-and-which-key)
- [5. M2: the encrypted new key](#5-m2-the-encrypted-new-key)
- [6. M3: authenticating the request](#6-m3-authenticating-the-request)
- [7. M4: proof the key was stored](#7-m4-proof-the-key-was-stored)
- [8. M5: authenticating the response](#8-m5-authenticating-the-response)
- [9. What the SHE module checks](#9-what-the-she-module-checks)
- [10. Summary table](#10-summary-table)

## 1. Overview

The host wants to write a new key into a slot of the SHE module. It does not send the new key
in plain text. Instead it proves it knows an **authorizing key** that the module already has,
and uses that key to encrypt and authenticate the request.

```
            Host                                            SHE module
  knows: UID, AuthID, K_AuthID, KEY_new, C_ID, F_ID     knows: UID, all stored keys
  ------------------------------------------------      -------------------------------
  K1 = KDF(K_AuthID, ENC_C)
  K2 = KDF(K_AuthID, MAC_C)
  M1 = UID | ID | AuthID
  M2 = ENC_CBC(K1, C_ID | F_ID | 0... | KEY_new)
  M3 = CMAC(K2, M1 | M2)
                      ------- M1, M2, M3 ------->
                                                        check M3, decrypt M2, check UID,
                                                        protection flags and counter,
                                                        store KEY_new in slot ID
                                                        K3 = KDF(KEY_new, ENC_C)
                                                        K4 = KDF(KEY_new, MAC_C)
                                                        M4 = UID | ID | AuthID | ENC_ECB(K3, C_ID | 1 | 0...)
                                                        M5 = CMAC(K4, M4)
                      <------ M4, M5 -----------
  compare M4, M5 with the values it
  computed itself -> key really stored
```

M1–M3 are keyed with the **old** (authorizing) key; M4–M5 are keyed with the **new** key.
Only a module that really decrypted and stored `KEY_new` can produce a correct M4 and M5.

### Inputs

| Symbol      | Size     | Meaning                                                            | Spec example                        |
|-------------|----------|--------------------------------------------------------------------|-------------------------------------|
| `UID`       | 120 bits | Unique ID of the SHE module (15 bytes)                             | `000000000000000000000000000001`    |
| `ID`        | 4 bits   | Slot being written                                                 | `4` (KEY_1)                         |
| `AuthID`    | 4 bits   | Slot whose key authorizes the write                                | `1` (MASTER_ECU_KEY)                |
| `K_AuthID`  | 128 bits | Value of the authorizing key                                       | `000102030405060708090a0b0c0d0e0f`  |
| `KEY_new`   | 128 bits | The new key                                                        | `0f0e0d0c0b0a09080706050403020100`  |
| `C_ID`      | 28 bits  | New counter for the slot; must be larger than the stored one      | `1`                                 |
| `F_ID`      | 5 bits   | New protection flags for the slot                                  | `0` (none)                          |

Notation: `|` is concatenation, `⊕` is XOR, `0(n)` is n zero bits, `E_K(x)` is AES-128
encryption of one 16-byte block `x` with key `K`. Bit counts are shown in brackets.

### Slot IDs

| ID  | Slot           | ID      | Slot            |
|-----|----------------|---------|-----------------|
| 0x0 | SECRET_KEY     | 0x4–0xD | KEY_1 … KEY_10  |
| 0x1 | MASTER_ECU_KEY | 0xE     | RAM_KEY         |
| 0x2 | BOOT_MAC_KEY   |         |                 |
| 0x3 | BOOT_MAC       |         |                 |

## 2. Building blocks

All four primitives use AES-128.

**AES-ECB** encrypts each 16-byte block independently: `C_i = E_K(P_i)`.

**AES-CBC with IV = 0** chains the blocks: `C_1 = E_K(P_1 ⊕ IV)`, `C_i = E_K(P_i ⊕ C_(i-1))`.

**AES-CMAC** (NIST SP 800-38B) is a 128-bit MAC over a message of any length:

```
L  = E_K(0(128))
K1' = L << 1,  XOR 0x87 into the last byte if the top bit of L was 1
K2' = K1' << 1, XOR 0x87 into the last byte if the top bit of K1' was 1
Split the message into 16-byte blocks M_1 … M_n.
If the last block is full:     M_n = M_n ⊕ K1'
otherwise pad it with 0x80 00…: M_n = pad(M_n) ⊕ K2'
X_0 = 0,  X_i = E_K(X_(i-1) ⊕ M_i),  CMAC = X_n
```

(`K1'`/`K2'` are CMAC's internal subkeys, not the SHE keys K1/K2 below.)

**Miyaguchi-Preneel (MP)** is a one-way compression function that turns data into a 128-bit
value, using AES with the running result as the key:

```
H_0 = 0(128)
H_i = E_(H_(i-1))(x_i) ⊕ x_i ⊕ H_(i-1)
MP(x_1 | … | x_n) = H_n
```

Code: `crypto.py` / `c/src/she_crypto.c`.

## 3. Key derivation: K1, K2, K3, K4

SHE never uses a stored key directly to encrypt or MAC the update messages. It derives a
separate key for each job with the **KDF**:

```
KDF(K, C) = MP(K | C)       two blocks: x_1 = K, x_2 = C
          = E_(H_1)(C) ⊕ C ⊕ H_1,   where H_1 = E_0(K) ⊕ K
```

The two constants make the encryption key and the MAC key different even though they come
from the same secret:

```
KEY_UPDATE_ENC_C = 0x01 01 53 48 45 00 80 00 00 00 00 00 00 00 00 B0
KEY_UPDATE_MAC_C = 0x01 02 53 48 45 00 80 00 00 00 00 00 00 00 00 B0
```

| Bytes        | Meaning                                                                 |
|--------------|-------------------------------------------------------------------------|
| `01`         | constant prefix                                                         |
| `01` / `02`  | 1 = encryption key (ENC_C), 2 = MAC key (MAC_C)                         |
| `53 48 45`   | ASCII `"SHE"`                                                           |
| `00`         | zero byte                                                               |
| `80 00 … 00` | MP padding: a single 1 bit followed by zeros                            |
| `B0`         | MP padding: message length = 0xB0 = 176 bits (128-bit key + 48 bits)    |

The constant already contains the MP padding for the 176-bit input `K | 01 0x 53 48 45 00`,
which is why the KDF is exactly two blocks with no extra padding block.

| Key | Formula                              | Used for            | Spec example value                  |
|-----|--------------------------------------|---------------------|-------------------------------------|
| K1  | `KDF(K_AuthID, KEY_UPDATE_ENC_C)`    | encrypt M2          | `118a46447a770d87828a69c222e2d17e`  |
| K2  | `KDF(K_AuthID, KEY_UPDATE_MAC_C)`    | MAC for M3          | `2ebb2a3da62dbd64b18ba6493e9fbe22`  |
| K3  | `KDF(KEY_new, KEY_UPDATE_ENC_C)`     | encrypt part of M4  | `ed2de7864a47f6bac319a9dc496a788f`  |
| K4  | `KDF(KEY_new, KEY_UPDATE_MAC_C)`     | MAC for M5          | `ec9386fefaa1c598246144343de5f26a`  |

Worked example for K1:

```
H_1 = E_0(000102030405060708090a0b0c0d0e0f) ⊕ 000102030405060708090a0b0c0d0e0f
    = 7acb0ddab8d3ea7b979e4c6d1aebac8d
E_(H_1)(KEY_UPDATE_ENC_C) = 6a4018d687a467fc151425af38097d43
K1  = 6a4018d687a467fc151425af38097d43
    ⊕ 010153484500800000000000000000b0     (KEY_UPDATE_ENC_C)
    ⊕ 7acb0ddab8d3ea7b979e4c6d1aebac8d     (H_1)
    = 118a46447a770d87828a69c222e2d17e
```

Code: `kdf()` in `crypto.py` / `she_kdf()` in `c/src/she_crypto.c`.

## 4. M1: who and which key

```
M1 = UID(120) | ID(4) | AuthID(4)                                   16 bytes
```

M1 is sent in clear. Bytes 0–14 are the UID; byte 15 holds the slot ID in the high nibble and
the AuthID in the low nibble: `byte15 = (ID << 4) | AuthID`.

```
UID = 000000000000000000000000000001, ID = 4, AuthID = 1   ->  byte15 = 0x41
M1  = 00000000000000000000000000000141
```

A UID of all zeros is the **wildcard UID**: the module accepts it only if the slot being
written already has the WILDCARD flag set.

Code: `build_m1()` / `she_build_m1()`.

## 5. M2: the encrypted new key

```
M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new(128) )   32 bytes
```

The plaintext is two blocks:

```
Block 1 (128 bits):  C_ID (28) | F_ID (5) | 0 (95)
Block 2 (128 bits):  KEY_new
```

The 5 flag bits of `F_ID`, from most to least significant:

| Bit | Flag                 | Effect when set                                               |
|-----|----------------------|---------------------------------------------------------------|
| 4   | WRITE_PROTECTION     | the slot can never be updated again                           |
| 3   | BOOT_PROTECTION      | key is unusable if secure boot failed                         |
| 2   | DEBUGGER_PROTECTION  | key is unusable while a debugger is attached                  |
| 1   | KEY_USAGE            | 0 = encryption/decryption key, 1 = MAC key                    |
| 0   | WILDCARD             | later updates of this slot may use the wildcard UID           |

As a number, block 1 is `(C_ID << 100) | (F_ID << 95)`. In bytes: the first 4 bytes are
`(C_ID << 4) | (F_ID >> 1)` (big endian), the top bit of byte 4 is `F_ID & 1`, and the rest is zero.

```
C_ID = 1, F_ID = 0:
  Block 1 = 00000010 00000000 00000000 00000000
  Block 2 = 0f0e0d0c 0b0a0908 07060504 03020100

CBC with K1 = 118a46447a770d87828a69c222e2d17e, IV = 0:
  C_1 = E_K1(Block 1 ⊕ 0)   = 2b111e2d93f486566bcbba1d7f7a9797
  C_2 = E_K1(Block 2 ⊕ C_1) = c94643b050fc5d4d7de14cff682203c3

M2 = 2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3
```

More examples of block 1:

| C_ID        | Flags            | F_ID   | Block 1                              |
|-------------|------------------|--------|--------------------------------------|
| 1           | none             | 0x00   | `00000010000000000000000000000000`   |
| 1           | WRITE_PROTECTION | 0x10   | `00000018000000000000000000000000`   |
| 5           | KEY_USAGE        | 0x02   | `00000051000000000000000000000000`   |
| 0x0ABCDEF   | WILDCARD         | 0x01   | `0abcdef0800000000000000000000000`   |

Code: `build_m2()` / `build_m2()` in `c/src/she_protocol.c`.

## 6. M3: authenticating the request

```
M3 = CMAC,K2( M1 | M2 )                                             16 bytes
```

CMAC over the 48 bytes of M1 followed by M2, keyed with K2. This proves the sender knows
`K_AuthID` and that neither M1 nor M2 was changed: flipping any bit of the UID, the slot IDs,
the counter, the flags or the encrypted key gives a different M3.

```
K2 = 2ebb2a3da62dbd64b18ba6493e9fbe22
M3 = CMAC(K2, 00000000000000000000000000000141 | 2b111e2d…682203c3)
   = b9d745e5ace7d41860bc63c2b9f5bb46
```

Code: `build_m3()` / `she_build_m3()`.

## 7. M4: proof the key was stored

```
M4 = UID(120) | ID(4) | AuthID(4) | ENC_ECB,K3( C_ID(28) | 1(1) | 0(99) )    32 bytes
```

The first 16 bytes repeat M1, but always with the module's **real** UID (even if the request
used the wildcard UID). The second 16 bytes are the counter followed by a single 1 bit,
encrypted with K3, which is derived from the new key:

```
counter block = (C_ID << 100) | (1 << 99)
              = 00000018 00000000 00000000 00000000      (C_ID = 1)

K3 = ed2de7864a47f6bac319a9dc496a788f
E_K3(counter block) = b472e8d8727d70d57295e74849a27917

M4 = 00000000000000000000000000000141 | b472e8d8727d70d57295e74849a27917
```

Because K3 comes from `KEY_new`, the module can only produce this value if it decrypted M2
correctly. The host can also decrypt this block with K3 to read back the counter the module
stored (`decode_m4_counter()` / `she_decode_m4_counter()`).

Code: `build_m4()` / `she_build_m4()`.

## 8. M5: authenticating the response

```
M5 = CMAC,K4( M4 )                                                  16 bytes
```

```
K4 = ec9386fefaa1c598246144343de5f26a
M5 = CMAC(K4, M4) = 820d8d95dc11b4668878160cb2a4e23e
```

The host computes M4 and M5 itself (it knows `KEY_new`) and compares them with what the module
returned. If both match, the new key, counter and flags are confirmed stored in slot `ID`.

Code: `build_m5()` / `she_build_m5()`, compared by `verify_response()` / `she_verify_response()`.

## 9. What the SHE module checks

When it receives M1, M2, M3 the module (and `emulator.py` / `c/src/she_emulator.c`) does:

1. **Slot rules.** `ID` must not be SECRET_KEY, and `AuthID` must be allowed to write `ID`:
   - KEY_1…KEY_10, MASTER_ECU_KEY, BOOT_MAC_KEY: MASTER_ECU_KEY or the key itself
   - BOOT_MAC: MASTER_ECU_KEY or BOOT_MAC_KEY
   - RAM_KEY: SECRET_KEY

   Otherwise `ERC_KEY_INVALID`.
2. **Authorizing key present.** The `AuthID` slot must hold a key, otherwise `ERC_KEY_EMPTY`.
3. **M3.** Recompute `CMAC(K2, M1 | M2)`; mismatch → `ERC_KEY_UPDATE_ERROR`.
4. **UID.** Must equal the module's UID, or be the wildcard UID with the slot's WILDCARD flag
   set; otherwise `ERC_KEY_UPDATE_ERROR`.
5. **Write protection.** If the slot's WRITE_PROTECTION flag is set → `ERC_KEY_WRITE_PROTECTED`.
6. **Decrypt M2** with K1 to get `C_ID`, `F_ID`, `KEY_new`.
7. **Counter.** `C_ID` must be strictly greater than the stored counter (prevents replaying an
   old update); otherwise `ERC_KEY_UPDATE_ERROR`. RAM_KEY has no counter and no flags.
8. **Store** `KEY_new`, `C_ID`, `F_ID` in slot `ID`, then build and return M4 and M5.

## 10. Summary table

| Message | Formula                                                   | Keyed with           | Size     | Spec example                                                          |
|---------|-----------------------------------------------------------|----------------------|----------|-----------------------------------------------------------------------|
| M1      | `UID \| ID \| AuthID`                                     | —                    | 16 bytes | `00000000000000000000000000000141`                                    |
| M2      | `ENC_CBC,K1,IV=0(C_ID \| F_ID \| 0(95) \| KEY_new)`       | K1 (from K_AuthID)   | 32 bytes | `2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3`    |
| M3      | `CMAC,K2(M1 \| M2)`                                       | K2 (from K_AuthID)   | 16 bytes | `b9d745e5ace7d41860bc63c2b9f5bb46`                                    |
| M4      | `UID \| ID \| AuthID \| ENC_ECB,K3(C_ID \| 1 \| 0(99))`   | K3 (from KEY_new)    | 32 bytes | `00000000000000000000000000000141b472e8d8727d70d57295e74849a27917`    |
| M5      | `CMAC,K4(M4)`                                             | K4 (from KEY_new)    | 16 bytes | `820d8d95dc11b4668878160cb2a4e23e`                                    |

To see these intermediate values for your own inputs, run the CLI with `--explain`:

```bash
she-update --explain                       # Python
c/build/she-update --explain               # C
```
