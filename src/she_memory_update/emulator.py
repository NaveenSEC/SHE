"""A software SHE module that processes CMD_LOAD_KEY the way the hardware does.

Check order when M1, M2, M3 arrive (see docs/PROTOCOL.md section 9):
    1. slot rules (ID / AuthID)            -> ERC_KEY_INVALID
    2. authorizing key present             -> ERC_KEY_EMPTY
    3. M3 == CMAC,K2(M1 | M2)              -> ERC_KEY_UPDATE_ERROR
    4. UID matches (or wildcard allowed)   -> ERC_KEY_UPDATE_ERROR
    5. slot not write protected            -> ERC_KEY_WRITE_PROTECTED
    6. decrypt M2 with K1
    7. new counter > stored counter        -> ERC_KEY_UPDATE_ERROR
    8. store key, answer with M4, M5
"""

from __future__ import annotations  # allow "set[int]" / "X | None" type hints on Python 3.10

import hmac  # compare_digest: constant-time MAC comparison
from dataclasses import dataclass, field  # record type for one key slot

from .protocol import (
    WILDCARD_UID,  # all-zero UID
    KeyFlags,  # the 5 protection flags
    KeySlot,  # slot ID numbers
    build_m3,  # recompute M3 to check the request
    build_m4,  # build the confirmation M4
    build_m5,  # build the confirmation MAC M5
    decode_m2,  # decrypt M2 into counter, flags, key
    parse_m1,  # split M1 into UID, ID, AuthID
)


class SheError(Exception):
    """A SHE error code returned instead of M4, M5."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")  # human-readable text, e.g. "ERC_KEY_EMPTY: ..."
        self.code = code  # machine-readable SHE error code


ERC_KEY_INVALID = "ERC_KEY_INVALID"  # slot can't be written, or AuthID may not write it
ERC_KEY_EMPTY = "ERC_KEY_EMPTY"  # the authorizing slot holds no key
ERC_KEY_WRITE_PROTECTED = "ERC_KEY_WRITE_PROTECTED"  # the target slot has WRITE_PROTECTION set
ERC_KEY_UPDATE_ERROR = "ERC_KEY_UPDATE_ERROR"  # bad M3, wrong UID or counter not increasing


@dataclass
class KeyEntry:
    """Contents of one key slot in the module's non-volatile memory."""

    key: bytes  # the 16-byte key value
    counter: int = 0  # C_ID of the last successful update
    flags: KeyFlags = field(default_factory=KeyFlags)  # F_ID of the last successful update


def _allowed_auth_ids(key_id: int) -> set[int]:
    """Which slots may authorize an update of ``key_id`` (SHE spec, CMD_LOAD_KEY)."""
    if key_id == KeySlot.RAM_KEY:  # RAM_KEY ...
        return {KeySlot.SECRET_KEY}  # ... is loaded with SECRET_KEY
    if key_id == KeySlot.BOOT_MAC:  # BOOT_MAC ...
        return {KeySlot.MASTER_ECU_KEY, KeySlot.BOOT_MAC_KEY}  # ... by the master key or BOOT_MAC_KEY
    # MASTER_ECU_KEY, BOOT_MAC_KEY and KEY_1..KEY_10: the master key or the key itself.
    return {KeySlot.MASTER_ECU_KEY, key_id}


class SheEmulator:
    def __init__(self, uid: bytes, secret_key: bytes | None = None) -> None:
        if len(uid) != 15:  # the module UID is 120 bits
            raise ValueError("UID must be 15 bytes")  # reject wrong sizes
        self.uid = uid  # this module's unique ID
        self.slots: dict[int, KeyEntry] = {}  # slot ID -> stored key; a missing entry means "empty"
        if secret_key is not None:  # SECRET_KEY is programmed at the factory
            self.slots[KeySlot.SECRET_KEY] = KeyEntry(secret_key)  # store it if given

    def provision(self, slot: int, key: bytes, counter: int = 0, flags: KeyFlags = KeyFlags()) -> None:
        """Factory-provision a slot directly (bypasses the update protocol)."""
        self.slots[slot] = KeyEntry(key, counter, flags)  # write the slot unconditionally

    def load_key(self, m1: bytes, m2: bytes, m3: bytes) -> tuple[bytes, bytes]:
        """Process CMD_LOAD_KEY and return (M4, M5), or raise SheError."""
        uid, key_id, auth_id = parse_m1(m1)  # M1 = UID | ID | AuthID

        # Step 1: slot rules. SECRET_KEY (0x0) and IDs above RAM_KEY (0xF) can never be written.
        if key_id == KeySlot.SECRET_KEY or key_id > KeySlot.RAM_KEY:
            raise SheError(ERC_KEY_INVALID, f"slot {key_id:#x} cannot be updated")
        if auth_id not in _allowed_auth_ids(key_id):  # is AuthID allowed to authorize this slot?
            raise SheError(ERC_KEY_INVALID, f"AuthID {auth_id:#x} may not update slot {key_id:#x}")

        # Step 2: the authorizing key K_AuthID must be present.
        auth = self.slots.get(auth_id)  # look up the authorizing slot
        if auth is None:  # never provisioned
            raise SheError(ERC_KEY_EMPTY, f"authorizing slot {auth_id:#x} is empty")

        # Step 3: authenticate the request. M3 must equal CMAC,K2(M1 | M2) with K2 = KDF(K_AuthID, MAC_C).
        if not hmac.compare_digest(build_m3(auth.key, m1, m2), m3):  # constant-time comparison
            raise SheError(ERC_KEY_UPDATE_ERROR, "M3 verification failed")  # tampered, or wrong K_AuthID

        # Step 4: the request must be for this module.
        current = self.slots.get(key_id)  # what the target slot holds now (None = empty)
        if uid != self.uid:  # not our UID ...
            # ... only accepted if it is the all-zero wildcard UID AND the slot has the WILDCARD flag.
            wildcard_ok = uid == WILDCARD_UID and current is not None and current.flags.wildcard
            if not wildcard_ok:
                raise SheError(ERC_KEY_UPDATE_ERROR, "UID mismatch")

        # Step 5: a write-protected slot can never be changed again.
        if current is not None and current.flags.write_protection:
            raise SheError(ERC_KEY_WRITE_PROTECTED, f"slot {key_id:#x} is write protected")

        # Step 6: decrypt M2 with K1 = KDF(K_AuthID, ENC_C) -> C_ID, F_ID, KEY_new.
        decoded = decode_m2(auth.key, m2)
        if key_id == KeySlot.RAM_KEY:
            # RAM_KEY has no counter and no flags.
            counter, flags = 0, KeyFlags()
        else:
            # Step 7: anti-replay. The new counter must be strictly greater than the stored one.
            if current is not None and decoded.counter <= current.counter:
                raise SheError(ERC_KEY_UPDATE_ERROR, "counter is not greater than the stored counter")
            counter, flags = decoded.counter, decoded.flags  # accept the new counter and flags

        # Step 8: store the key, then prove it with M4/M5 keyed by the NEW key.
        self.slots[key_id] = KeyEntry(decoded.key, counter, flags)  # write the slot

        m4 = build_m4(self.uid, key_id, auth_id, decoded.key, counter)  # always the module's real UID
        return m4, build_m5(decoded.key, m4)  # (M4, M5 = CMAC,K4(M4))
