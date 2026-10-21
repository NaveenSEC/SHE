"""SHE CMD_LOAD_KEY memory update protocol (M1..M5).

Host side: build M1, M2, M3 for a key update and compute the M4, M5 the SHE
module must answer with, then verify the response received from the module.

See docs/PROTOCOL.md for a step-by-step explanation with worked values.

Message layout (SHE 1.1, 5-bit flag field)::

    M1 = UID(120) | ID(4) | AuthID(4)
    M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new(128) )
    M3 = CMAC,K2( M1 | M2 )
    M4 = UID(120) | ID(4) | AuthID(4) | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )
    M5 = CMAC,K4( M4 )

    K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)    K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C)
    K3 = KDF(KEY_new, KEY_UPDATE_ENC_C)     K4 = KDF(KEY_new, KEY_UPDATE_MAC_C)

Bit positions inside a 128-bit block are counted from 127 (most significant,
first byte) down to 0. So "C_ID(28) | F_ID(5) | 0(95)" puts C_ID in bits
127..100, F_ID in bits 99..95 and zeros in bits 94..0, i.e. the block equals
the integer (C_ID << 100) | (F_ID << 95).
"""

from __future__ import annotations  # allow "tuple[bytes, int, int]" style type hints on Python 3.10

import hmac  # compare_digest: constant-time comparison of MACs
from dataclasses import dataclass  # simple immutable records for flags and messages
from enum import IntEnum  # key slot numbers that also behave like ints

from .crypto import (
    KEY_UPDATE_ENC_C,  # KDF constant for encryption keys (K1, K3)
    KEY_UPDATE_MAC_C,  # KDF constant for MAC keys (K2, K4)
    cbc_decrypt,  # used to decode M2
    cbc_encrypt,  # used to build M2
    cmac,  # used for M3 and M5
    ecb_decrypt,  # used to decode the counter block of M4
    ecb_encrypt,  # used to build the counter block of M4
    kdf,  # KDF(K, C) = Miyaguchi-Preneel(K | C)
)

UID_SIZE = 15  # the SHE UID is 120 bits = 15 bytes
WILDCARD_UID = bytes(UID_SIZE)  # all-zero UID: "any module", only allowed if the slot's WILDCARD flag is set
MAX_COUNTER = (1 << 28) - 1  # C_ID is 28 bits, so the largest counter is 2^28 - 1 = 0x0FFFFFFF


class KeySlot(IntEnum):
    """SHE key slot IDs: the 4-bit ID / AuthID values used in M1 and M4."""

    SECRET_KEY = 0x0  # factory secret; can never be loaded via CMD_LOAD_KEY
    MASTER_ECU_KEY = 0x1  # master key: may authorize updates of every other slot except SECRET_KEY
    BOOT_MAC_KEY = 0x2  # key used to compute the secure-boot MAC
    BOOT_MAC = 0x3  # stored reference MAC of the bootloader
    KEY_1 = 0x4  # general purpose key slots KEY_1 .. KEY_10
    KEY_2 = 0x5
    KEY_3 = 0x6
    KEY_4 = 0x7
    KEY_5 = 0x8
    KEY_6 = 0x9
    KEY_7 = 0xA
    KEY_8 = 0xB
    KEY_9 = 0xC
    KEY_10 = 0xD
    RAM_KEY = 0xE  # volatile key; loaded with SECRET_KEY as the authorizing key, no counter/flags


@dataclass(frozen=True)
class KeyFlags:
    """The 5 protection flags F_ID stored with a key (SHE 1.1)."""

    write_protection: bool = False  # WP: once set, the slot can never be updated again
    boot_protection: bool = False  # BP: key is unusable if secure boot failed
    debugger_protection: bool = False  # DP: key is unusable while a debugger is attached
    key_usage: bool = False  # KU: 0 = encryption/decryption key, 1 = MAC key
    wildcard: bool = False  # WC: later updates of this slot may use the wildcard UID

    def to_bits(self) -> int:
        """Pack into the 5-bit F_ID field: F_ID = WP<<4 | BP<<3 | DP<<2 | KU<<1 | WC."""
        return (
            self.write_protection << 4  # bit 4 (MSB): write protection
            | self.boot_protection << 3  # bit 3: boot protection
            | self.debugger_protection << 2  # bit 2: debugger protection
            | self.key_usage << 1  # bit 1: key usage
            | self.wildcard  # bit 0 (LSB): wildcard
        )

    @classmethod
    def from_bits(cls, bits: int) -> "KeyFlags":
        """Unpack a 5-bit F_ID value into named flags (inverse of to_bits)."""
        return cls(
            write_protection=bool(bits & 0x10),  # bit 4 = 0b10000
            boot_protection=bool(bits & 0x08),  # bit 3 = 0b01000
            debugger_protection=bool(bits & 0x04),  # bit 2 = 0b00100
            key_usage=bool(bits & 0x02),  # bit 1 = 0b00010
            wildcard=bool(bits & 0x01),  # bit 0 = 0b00001
        )


@dataclass(frozen=True)
class KeyUpdateMessages:
    """The full set of messages for one key update."""

    m1: bytes  # 16 bytes, request header (sent to the module)
    m2: bytes  # 32 bytes, encrypted counter/flags/new key (sent to the module)
    m3: bytes  # 16 bytes, CMAC over M1 | M2 (sent to the module)
    m4: bytes  # 32 bytes, expected confirmation from the module
    m5: bytes  # 16 bytes, expected CMAC over M4 from the module


@dataclass(frozen=True)
class DecodedM2:
    """The plaintext fields carried inside M2."""

    counter: int  # C_ID, 28 bits
    flags: KeyFlags  # F_ID, 5 bits
    key: bytes  # KEY_new, 16 bytes


def _check_uid(uid: bytes) -> None:
    if len(uid) != UID_SIZE:  # UID must be exactly 120 bits
        raise ValueError(f"UID must be {UID_SIZE} bytes, got {len(uid)}")  # reject wrong sizes


def _check_counter(counter: int) -> None:
    if not 0 <= counter <= MAX_COUNTER:  # 0 <= C_ID <= 2^28 - 1
        raise ValueError("counter must fit in 28 bits")  # a larger value would overflow the C_ID field


def build_m1(uid: bytes, key_id: int, auth_id: int) -> bytes:
    """M1 = UID(120) | ID(4) | AuthID(4); the last byte is (ID << 4) | AuthID."""
    _check_uid(uid)  # UID must be 15 bytes
    return uid + bytes([(key_id & 0xF) << 4 | (auth_id & 0xF)])  # 15 UID bytes + one byte: ID high nibble, AuthID low


def build_m2(auth_key: bytes, counter: int, flags: KeyFlags, new_key: bytes) -> bytes:
    """M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new ), K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)."""
    _check_counter(counter)  # C_ID must fit in 28 bits
    if len(new_key) != 16:  # KEY_new must be a 128-bit AES key
        raise ValueError("new key must be 16 bytes")  # reject wrong sizes
    # Block 1 = C_ID(28) | F_ID(5) | 0(95) = (C_ID << 100) | (F_ID << 95), as 16 big-endian bytes.
    header = (counter << 100 | flags.to_bits() << 95).to_bytes(16, "big")
    k1 = kdf(auth_key, KEY_UPDATE_ENC_C)  # K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)
    return cbc_encrypt(k1, header + new_key)  # M2 = CBC-encrypt (block 1 | KEY_new) with K1 and IV = 0


def build_m3(auth_key: bytes, m1: bytes, m2: bytes) -> bytes:
    """M3 = CMAC,K2( M1 | M2 ), K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C)."""
    k2 = kdf(auth_key, KEY_UPDATE_MAC_C)  # K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C)
    return cmac(k2, m1 + m2)  # M3 = CMAC over the 48 bytes M1 | M2


def build_m4(uid: bytes, key_id: int, auth_id: int, new_key: bytes, counter: int) -> bytes:
    """M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) ), K3 = KDF(KEY_new, KEY_UPDATE_ENC_C)."""
    _check_counter(counter)  # C_ID must fit in 28 bits
    k3 = kdf(new_key, KEY_UPDATE_ENC_C)  # K3 = KDF(KEY_new, KEY_UPDATE_ENC_C): derived from the NEW key
    # Counter block = C_ID(28) | 1 | 0(99) = (C_ID << 100) | (1 << 99), as 16 big-endian bytes.
    block = (counter << 100 | 1 << 99).to_bytes(16, "big")
    return build_m1(uid, key_id, auth_id) + ecb_encrypt(k3, block)  # M4 = (same layout as M1) | E_K3(counter block)


def build_m5(new_key: bytes, m4: bytes) -> bytes:
    """M5 = CMAC,K4( M4 ), K4 = KDF(KEY_new, KEY_UPDATE_MAC_C)."""
    k4 = kdf(new_key, KEY_UPDATE_MAC_C)  # K4 = KDF(KEY_new, KEY_UPDATE_MAC_C): derived from the NEW key
    return cmac(k4, m4)  # M5 = CMAC over the 32 bytes of M4


def build_key_update(
    uid: bytes,  # 15-byte UID of the target SHE module (or WILDCARD_UID)
    key_id: int,  # ID: slot to write
    auth_id: int,  # AuthID: slot whose key authorizes the write
    auth_key: bytes,  # K_AuthID: value of the authorizing key
    new_key: bytes,  # KEY_new: the key to store
    counter: int,  # C_ID: new counter, must exceed the slot's current counter
    flags: KeyFlags = KeyFlags(),  # F_ID: new protection flags (default: none)
) -> KeyUpdateMessages:
    """Build the M1..M3 request and the expected M4, M5 response."""
    m1 = build_m1(uid, key_id, auth_id)  # M1 = UID | ID | AuthID
    m2 = build_m2(auth_key, counter, flags, new_key)  # M2 = ENC_CBC,K1(C_ID | F_ID | 0 | KEY_new)
    m3 = build_m3(auth_key, m1, m2)  # M3 = CMAC,K2(M1 | M2)
    m4 = build_m4(uid, key_id, auth_id, new_key, counter)  # M4 = UID | ID | AuthID | ENC_ECB,K3(C_ID | 1 | 0)
    m5 = build_m5(new_key, m4)  # M5 = CMAC,K4(M4)
    return KeyUpdateMessages(m1, m2, m3, m4, m5)  # bundle all five messages


def parse_m1(m1: bytes) -> tuple[bytes, int, int]:
    """Return (uid, key_id, auth_id)."""
    if len(m1) != 16:  # M1 is always 128 bits
        raise ValueError("M1 must be 16 bytes")  # reject wrong sizes
    return m1[:UID_SIZE], m1[15] >> 4, m1[15] & 0xF  # UID = bytes 0..14, ID = high nibble, AuthID = low nibble


def decode_m2(auth_key: bytes, m2: bytes) -> DecodedM2:
    """Decrypt M2 with K1 and split it into C_ID, F_ID and KEY_new (what the SHE module does)."""
    if len(m2) != 32:  # M2 is always 256 bits
        raise ValueError("M2 must be 32 bytes")  # reject wrong sizes
    k1 = kdf(auth_key, KEY_UPDATE_ENC_C)  # K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)
    plain = cbc_decrypt(k1, m2)  # plaintext = block 1 | KEY_new
    header = int.from_bytes(plain[:16], "big")  # block 1 as a 128-bit integer
    return DecodedM2(
        counter=header >> 100,  # C_ID = bits 127..100
        flags=KeyFlags.from_bits((header >> 95) & 0x1F),  # F_ID = bits 99..95 (5 bits)
        key=plain[16:],  # KEY_new = block 2
    )


def decode_m4_counter(new_key: bytes, m4: bytes) -> int:
    """Decrypt the M4 counter block; raise if its marker bit is missing."""
    if len(m4) != 32:  # M4 is always 256 bits
        raise ValueError("M4 must be 32 bytes")  # reject wrong sizes
    k3 = kdf(new_key, KEY_UPDATE_ENC_C)  # K3 = KDF(KEY_new, KEY_UPDATE_ENC_C)
    value = int.from_bytes(ecb_decrypt(k3, m4[16:]), "big")  # counter block = D_K3(second half of M4)
    if value & ((1 << 100) - 1) != 1 << 99:  # bits 99..0 must be exactly "1 followed by 99 zeros"
        raise ValueError("M4 counter block is malformed")  # wrong key, or the module stored something else
    return value >> 100  # C_ID = bits 127..100


def verify_response(expected: KeyUpdateMessages, m4: bytes, m5: bytes) -> bool:
    """Constant-time check that the module's M4, M5 match what the host expects."""
    # compare_digest takes the same time wherever the bytes differ; "&" (not "and") so both are always checked.
    return hmac.compare_digest(expected.m4, m4) & hmac.compare_digest(expected.m5, m5)
