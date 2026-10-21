# SHE Memory Update Protocol — C implementation

A C99 port of the Python package in this repository: SHE `CMD_LOAD_KEY` message builder
(M1–M5), a SHE module emulator, and the SHE crypto (AES-128 ECB/CBC, AES-CMAC,
Miyaguchi-Preneel KDF).

- No dependencies beyond the C standard library; AES is implemented in `src/she_crypto.c`.
- No heap allocation, so the library can go straight into microcontroller firmware.
- Compiles cleanly as C++ too; the headers have `extern "C"` guards.

## Build and test

```bash
cmake -S c -B c/build
cmake --build c/build
ctest --test-dir c/build --output-on-failure
```

In VS Code, the **CMake Tools** extension builds the project; the tests then appear in the
Testing view (flask icon in the left Activity Bar). The launch configurations
*C: run spec example*, *C: print messages for a real ECU* and *C: debug tests* run under the debugger.

## Command line

```bash
c/build/she-update                 # SHE spec example, run through the emulator
c/build/she-update --no-emulate    # just print M1-M5 for a real ECU
c/build/she-update --key-id KEY_3 --auth-key 000102030405060708090a0b0c0d0e0f \
                   --new-key 00112233445566778899aabbccddeeff --counter 2 --write-protection
```

Options match the Python CLI: `--uid`, `--key-id`, `--auth-id`, `--auth-key`, `--new-key`,
`--counter`, `--write-protection`, `--boot-protection`, `--debugger-protection`,
`--key-usage`, `--wildcard`, `--no-emulate`, `--explain` (prints K1–K4 and the plaintext of
each message; see [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md)). (On Windows the program is
`c\build\Debug\she-update.exe`.)

## Library use

```c
#include "she.h"

she_messages_t msgs;
she_build_key_update(uid, SHE_KEY_1, SHE_MASTER_ECU_KEY, master_key, new_key,
                     /*counter=*/1, /*flags=*/NULL, &msgs);

/* send msgs.m1, msgs.m2, msgs.m3 to the SHE module, receive m4 and m5 ... */

if (!she_verify_response(&msgs, m4, m5)) {
    /* key was not stored */
}
```

On a real MCU you normally only need `she_crypto.c` and `she_protocol.c` (the host side);
`she_emulator.c` is for testing without hardware.

## Files

```
include/she.h          protocol + emulator API
include/she_crypto.h   AES, CMAC, Miyaguchi-Preneel, KDF
src/she_crypto.c       crypto implementation
src/aes_tables.inc     AES S-boxes
src/she_protocol.c     M1..M5 build/decode/verify
src/she_emulator.c     SHE module emulator
src/main.c             she-update CLI
tests/test_she.c       tests: NIST/RFC 4493/SHE spec vectors, protocol, emulator rejections
```

As with the Python version, flags use the 5-bit SHE 1.1 field; SHE+ chips with a 6-bit field
(`VERIFY_ONLY`) need a change in `she_flags_to_bits`, `build_m2` and `she_decode_m2`.
