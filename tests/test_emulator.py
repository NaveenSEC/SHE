import pytest

from she_memory_update import KeyFlags, KeySlot, SheEmulator, SheError, build_key_update, verify_response
from she_memory_update.emulator import (
    ERC_KEY_EMPTY,
    ERC_KEY_INVALID,
    ERC_KEY_UPDATE_ERROR,
    ERC_KEY_WRITE_PROTECTED,
)
from she_memory_update.protocol import WILDCARD_UID

from .conftest import MASTER_KEY, NEW_KEY, UID


def update(key_id=KeySlot.KEY_1, auth_id=KeySlot.MASTER_ECU_KEY, auth_key=MASTER_KEY,
           new_key=NEW_KEY, counter=1, flags=KeyFlags(), uid=UID):
    return build_key_update(uid, key_id, auth_id, auth_key, new_key, counter, flags)


def send(she, msgs):
    return she.load_key(msgs.m1, msgs.m2, msgs.m3)


def expect_error(code, she, m1, m2, m3):
    with pytest.raises(SheError) as exc:
        she.load_key(m1, m2, m3)
    assert exc.value.code == code


def test_spec_update_verified(she):
    msgs = update()
    m4, m5 = send(she, msgs)
    assert verify_response(msgs, m4, m5)
    entry = she.slots[KeySlot.KEY_1]
    assert (entry.key, entry.counter) == (NEW_KEY, 1)


def test_tampered_m2(she):
    msgs = update()
    m2 = bytes([msgs.m2[0] ^ 1]) + msgs.m2[1:]
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, m2, msgs.m3)


def test_tampered_m3(she):
    msgs = update()
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, bytes(16))


def test_wrong_auth_key(she):
    msgs = update(auth_key=bytes(16))
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, msgs.m3)


def test_replay_rejected(she):
    msgs = update()
    send(she, msgs)
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, msgs.m3)


def test_counter_must_increase(she):
    send(she, update(counter=5))
    msgs = update(counter=5, new_key=bytes(16))
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, msgs.m3)
    send(she, update(counter=6, new_key=bytes(16)))
    assert she.slots[KeySlot.KEY_1].counter == 6


def test_uid_mismatch(she):
    msgs = update(uid=bytes(14) + b"\x02")
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, msgs.m3)


def test_wildcard_uid_needs_wildcard_flag(she):
    msgs = update(uid=WILDCARD_UID)
    expect_error(ERC_KEY_UPDATE_ERROR, she, msgs.m1, msgs.m2, msgs.m3)


def test_wildcard_uid_allowed_when_flag_set(she):
    she.provision(KeySlot.KEY_1, bytes(16), counter=1, flags=KeyFlags(wildcard=True))
    msgs = update(uid=WILDCARD_UID, counter=2)
    m4, _ = send(she, msgs)
    # The module answers with its real UID, not the wildcard.
    assert m4[:15] == UID


def test_write_protected(she):
    send(she, update(flags=KeyFlags(write_protection=True)))
    msgs = update(counter=2, new_key=bytes(16))
    expect_error(ERC_KEY_WRITE_PROTECTED, she, msgs.m1, msgs.m2, msgs.m3)


def test_unauthorized_auth_id(she):
    she.provision(KeySlot.KEY_2, MASTER_KEY)
    msgs = update(auth_id=KeySlot.KEY_2)
    expect_error(ERC_KEY_INVALID, she, msgs.m1, msgs.m2, msgs.m3)


def test_secret_key_cannot_be_loaded(she):
    msgs = update(key_id=KeySlot.SECRET_KEY)
    expect_error(ERC_KEY_INVALID, she, msgs.m1, msgs.m2, msgs.m3)


def test_empty_auth_key():
    she = SheEmulator(UID)
    msgs = update()
    expect_error(ERC_KEY_EMPTY, she, msgs.m1, msgs.m2, msgs.m3)


def test_key_can_authorize_itself(she):
    send(she, update())
    msgs = update(auth_id=KeySlot.KEY_1, auth_key=NEW_KEY, new_key=bytes(16), counter=2)
    m4, m5 = send(she, msgs)
    assert verify_response(msgs, m4, m5)


def test_load_ram_key():
    secret = bytes(range(16, 32))
    she = SheEmulator(UID, secret_key=secret)
    msgs = update(key_id=KeySlot.RAM_KEY, auth_id=KeySlot.SECRET_KEY, auth_key=secret, counter=0)
    m4, m5 = send(she, msgs)
    assert verify_response(msgs, m4, m5)
    assert she.slots[KeySlot.RAM_KEY].key == NEW_KEY


def test_rotate_master_ecu_key(she):
    new_master = bytes(range(32, 48))
    msgs = update(key_id=KeySlot.MASTER_ECU_KEY, new_key=new_master)
    m4, m5 = send(she, msgs)
    assert verify_response(msgs, m4, m5)
    # The old master key no longer authorizes updates.
    stale = update(counter=1)
    expect_error(ERC_KEY_UPDATE_ERROR, she, stale.m1, stale.m2, stale.m3)
    fresh = update(auth_key=new_master)
    send(she, fresh)


def test_boot_mac_by_boot_mac_key(she):
    she.provision(KeySlot.BOOT_MAC_KEY, bytes(16))
    msgs = update(key_id=KeySlot.BOOT_MAC, auth_id=KeySlot.BOOT_MAC_KEY, auth_key=bytes(16))
    send(she, msgs)


def test_bad_uid_length():
    with pytest.raises(ValueError):
        SheEmulator(bytes(14))
