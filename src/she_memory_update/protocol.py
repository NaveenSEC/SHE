"""SHE CMD_LOAD_KEY memory update protocol (M1..M5).

Host side: build M1, M2, M3 for a key update and compute the M4, M5 the SHE
module must answer with, then verify the response received from the module.

Message layout (SHE 1.1, 5-bit flag field)::

    M1 = UID(120) | ID(4) | AuthID(4)
    M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new(128) )
    M3 = CMAC,K2( M1 | M2 )
    M4 = UID(120) | ID(4) | AuthID(4) | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )
    M5 = CMAC,K4( M4 )

    K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C)    K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C)
    K3 = KDF(KEY_new, KEY_UPDATE_ENC_C)     K4 = KDF(KEY_new, KEY_UPDATE_MAC_C)
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import IntEnum

from .crypto import (
    KEY_UPDATE_ENC_C,
    KEY_UPDATE_MAC_C,
    cbc_decrypt,
    cbc_encrypt,
    cmac,
    ecb_decrypt,
    ecb_encrypt,
    kdf,
)

UID_SIZE = 15
WILDCARD_UID = bytes(UID_SIZE)
MAX_COUNTER = (1 << 28) - 1


class KeySlot(IntEnum):
    SECRET_KEY = 0x0
    MASTER_ECU_KEY = 0x1
    BOOT_MAC_KEY = 0x2
    BOOT_MAC = 0x3
    KEY_1 = 0x4
    KEY_2 = 0x5
    KEY_3 = 0x6
    KEY_4 = 0x7
    KEY_5 = 0x8
    KEY_6 = 0x9
    KEY_7 = 0xA
    KEY_8 = 0xB
    KEY_9 = 0xC
    KEY_10 = 0xD
    RAM_KEY = 0xE


@dataclass(frozen=True)
class KeyFlags:
    write_protection: bool = False
    boot_protection: bool = False
    debugger_protection: bool = False
    key_usage: bool = False
    wildcard: bool = False

    def to_bits(self) -> int:
        """Pack into the 5-bit F_ID field (write protection is the MSB)."""
        return (
            self.write_protection << 4
            | self.boot_protection << 3
            | self.debugger_protection << 2
            | self.key_usage << 1
            | self.wildcard
        )

    @classmethod
    def from_bits(cls, bits: int) -> "KeyFlags":
        return cls(
            write_protection=bool(bits & 0x10),
            boot_protection=bool(bits & 0x08),
            debugger_protection=bool(bits & 0x04),
            key_usage=bool(bits & 0x02),
            wildcard=bool(bits & 0x01),
        )


@dataclass(frozen=True)
class KeyUpdateMessages:
    m1: bytes
    m2: bytes
    m3: bytes
    m4: bytes
    m5: bytes


@dataclass(frozen=True)
class DecodedM2:
    counter: int
    flags: KeyFlags
    key: bytes


def _check_uid(uid: bytes) -> None:
    if len(uid) != UID_SIZE:
        raise ValueError(f"UID must be {UID_SIZE} bytes, got {len(uid)}")


def _check_counter(counter: int) -> None:
    if not 0 <= counter <= MAX_COUNTER:
        raise ValueError("counter must fit in 28 bits")


def build_m1(uid: bytes, key_id: int, auth_id: int) -> bytes:
    _check_uid(uid)
    return uid + bytes([(key_id & 0xF) << 4 | (auth_id & 0xF)])


def build_m2(auth_key: bytes, counter: int, flags: KeyFlags, new_key: bytes) -> bytes:
    _check_counter(counter)
    if len(new_key) != 16:
        raise ValueError("new key must be 16 bytes")
    # C_ID(28) | F_ID(5) | 0(95) occupies the first 128-bit block.
    header = (counter << 100 | flags.to_bits() << 95).to_bytes(16, "big")
    k1 = kdf(auth_key, KEY_UPDATE_ENC_C)
    return cbc_encrypt(k1, header + new_key)


def build_m3(auth_key: bytes, m1: bytes, m2: bytes) -> bytes:
    k2 = kdf(auth_key, KEY_UPDATE_MAC_C)
    return cmac(k2, m1 + m2)


def build_m4(uid: bytes, key_id: int, auth_id: int, new_key: bytes, counter: int) -> bytes:
    _check_counter(counter)
    k3 = kdf(new_key, KEY_UPDATE_ENC_C)
    # C_ID(28) | 1 | 0(99)
    block = (counter << 100 | 1 << 99).to_bytes(16, "big")
    return build_m1(uid, key_id, auth_id) + ecb_encrypt(k3, block)


def build_m5(new_key: bytes, m4: bytes) -> bytes:
    k4 = kdf(new_key, KEY_UPDATE_MAC_C)
    return cmac(k4, m4)


def build_key_update(
    uid: bytes,
    key_id: int,
    auth_id: int,
    auth_key: bytes,
    new_key: bytes,
    counter: int,
    flags: KeyFlags = KeyFlags(),
) -> KeyUpdateMessages:
    """Build the M1..M3 request and the expected M4, M5 response."""
    m1 = build_m1(uid, key_id, auth_id)
    m2 = build_m2(auth_key, counter, flags, new_key)
    m3 = build_m3(auth_key, m1, m2)
    m4 = build_m4(uid, key_id, auth_id, new_key, counter)
    m5 = build_m5(new_key, m4)
    return KeyUpdateMessages(m1, m2, m3, m4, m5)


def parse_m1(m1: bytes) -> tuple[bytes, int, int]:
    """Return (uid, key_id, auth_id)."""
    if len(m1) != 16:
        raise ValueError("M1 must be 16 bytes")
    return m1[:UID_SIZE], m1[15] >> 4, m1[15] & 0xF


def decode_m2(auth_key: bytes, m2: bytes) -> DecodedM2:
    if len(m2) != 32:
        raise ValueError("M2 must be 32 bytes")
    k1 = kdf(auth_key, KEY_UPDATE_ENC_C)
    plain = cbc_decrypt(k1, m2)
    header = int.from_bytes(plain[:16], "big")
    return DecodedM2(
        counter=header >> 100,
        flags=KeyFlags.from_bits((header >> 95) & 0x1F),
        key=plain[16:],
    )


def decode_m4_counter(new_key: bytes, m4: bytes) -> int:
    """Decrypt the M4 counter block; raise if its marker bit is missing."""
    if len(m4) != 32:
        raise ValueError("M4 must be 32 bytes")
    k3 = kdf(new_key, KEY_UPDATE_ENC_C)
    value = int.from_bytes(ecb_decrypt(k3, m4[16:]), "big")
    if value & ((1 << 100) - 1) != 1 << 99:
        raise ValueError("M4 counter block is malformed")
    return value >> 100


def verify_response(expected: KeyUpdateMessages, m4: bytes, m5: bytes) -> bool:
    """Constant-time check that the module's M4, M5 match what the host expects."""
    return hmac.compare_digest(expected.m4, m4) & hmac.compare_digest(expected.m5, m5)
