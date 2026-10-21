"""A software SHE module that processes CMD_LOAD_KEY the way the hardware does."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from .protocol import (
    WILDCARD_UID,
    KeyFlags,
    KeySlot,
    build_m3,
    build_m4,
    build_m5,
    decode_m2,
    parse_m1,
)


class SheError(Exception):
    """A SHE error code returned instead of M4, M5."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


ERC_KEY_INVALID = "ERC_KEY_INVALID"
ERC_KEY_EMPTY = "ERC_KEY_EMPTY"
ERC_KEY_WRITE_PROTECTED = "ERC_KEY_WRITE_PROTECTED"
ERC_KEY_UPDATE_ERROR = "ERC_KEY_UPDATE_ERROR"


@dataclass
class KeyEntry:
    key: bytes
    counter: int = 0
    flags: KeyFlags = field(default_factory=KeyFlags)


def _allowed_auth_ids(key_id: int) -> set[int]:
    """Which slots may authorize an update of ``key_id`` (SHE spec, CMD_LOAD_KEY)."""
    if key_id == KeySlot.RAM_KEY:
        return {KeySlot.SECRET_KEY}
    if key_id == KeySlot.BOOT_MAC:
        return {KeySlot.MASTER_ECU_KEY, KeySlot.BOOT_MAC_KEY}
    # MASTER_ECU_KEY, BOOT_MAC_KEY and KEY_1..KEY_10: the master key or the key itself.
    return {KeySlot.MASTER_ECU_KEY, key_id}


class SheEmulator:
    def __init__(self, uid: bytes, secret_key: bytes | None = None) -> None:
        if len(uid) != 15:
            raise ValueError("UID must be 15 bytes")
        self.uid = uid
        self.slots: dict[int, KeyEntry] = {}
        if secret_key is not None:
            self.slots[KeySlot.SECRET_KEY] = KeyEntry(secret_key)

    def provision(self, slot: int, key: bytes, counter: int = 0, flags: KeyFlags = KeyFlags()) -> None:
        """Factory-provision a slot directly (bypasses the update protocol)."""
        self.slots[slot] = KeyEntry(key, counter, flags)

    def load_key(self, m1: bytes, m2: bytes, m3: bytes) -> tuple[bytes, bytes]:
        """Process CMD_LOAD_KEY and return (M4, M5), or raise SheError."""
        uid, key_id, auth_id = parse_m1(m1)

        if key_id == KeySlot.SECRET_KEY or key_id > KeySlot.RAM_KEY:
            raise SheError(ERC_KEY_INVALID, f"slot {key_id:#x} cannot be updated")
        if auth_id not in _allowed_auth_ids(key_id):
            raise SheError(ERC_KEY_INVALID, f"AuthID {auth_id:#x} may not update slot {key_id:#x}")

        auth = self.slots.get(auth_id)
        if auth is None:
            raise SheError(ERC_KEY_EMPTY, f"authorizing slot {auth_id:#x} is empty")

        if not hmac.compare_digest(build_m3(auth.key, m1, m2), m3):
            raise SheError(ERC_KEY_UPDATE_ERROR, "M3 verification failed")

        current = self.slots.get(key_id)
        if uid != self.uid:
            wildcard_ok = uid == WILDCARD_UID and current is not None and current.flags.wildcard
            if not wildcard_ok:
                raise SheError(ERC_KEY_UPDATE_ERROR, "UID mismatch")

        if current is not None and current.flags.write_protection:
            raise SheError(ERC_KEY_WRITE_PROTECTED, f"slot {key_id:#x} is write protected")

        decoded = decode_m2(auth.key, m2)
        if key_id == KeySlot.RAM_KEY:
            # RAM_KEY has no counter and no flags.
            counter, flags = 0, KeyFlags()
        else:
            if current is not None and decoded.counter <= current.counter:
                raise SheError(ERC_KEY_UPDATE_ERROR, "counter is not greater than the stored counter")
            counter, flags = decoded.counter, decoded.flags

        self.slots[key_id] = KeyEntry(decoded.key, counter, flags)

        m4 = build_m4(self.uid, key_id, auth_id, decoded.key, counter)
        return m4, build_m5(decoded.key, m4)
