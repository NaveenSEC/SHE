import pytest

from she_memory_update.protocol import (
    KeyFlags,
    KeySlot,
    build_key_update,
    build_m1,
    build_m2,
    decode_m2,
    decode_m4_counter,
    parse_m1,
    verify_response,
)

from .conftest import MASTER_KEY, NEW_KEY, UID

# Example from the SHE functional specification (CMD_LOAD_KEY).
SPEC = {
    "m1": "00000000000000000000000000000141",
    "m2": "2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3",
    "m3": "b9d745e5ace7d41860bc63c2b9f5bb46",
    "m4": "00000000000000000000000000000141b472e8d8727d70d57295e74849a27917",
    "m5": "820d8d95dc11b4668878160cb2a4e23e",
}


@pytest.fixture
def spec_msgs():
    return build_key_update(UID, KeySlot.KEY_1, KeySlot.MASTER_ECU_KEY, MASTER_KEY, NEW_KEY, counter=1)


@pytest.mark.parametrize("name", list(SPEC))
def test_matches_spec_example(spec_msgs, name):
    assert getattr(spec_msgs, name).hex() == SPEC[name]


def test_flags_roundtrip():
    for bits in range(32):
        assert KeyFlags.from_bits(bits).to_bits() == bits
    assert KeyFlags(write_protection=True).to_bits() == 0x10
    assert KeyFlags(wildcard=True).to_bits() == 0x01


def test_m1_parse_roundtrip():
    assert parse_m1(build_m1(UID, 0x4, 0x1)) == (UID, 0x4, 0x1)


def test_m2_decode_roundtrip():
    flags = KeyFlags(write_protection=True, key_usage=True)
    m2 = build_m2(MASTER_KEY, 0x0ABCDEF, flags, NEW_KEY)
    decoded = decode_m2(MASTER_KEY, m2)
    assert (decoded.counter, decoded.flags, decoded.key) == (0x0ABCDEF, flags, NEW_KEY)


def test_m4_counter_decode(spec_msgs):
    assert decode_m4_counter(NEW_KEY, spec_msgs.m4) == 1
    with pytest.raises(ValueError):
        decode_m4_counter(MASTER_KEY, spec_msgs.m4)


def test_verify_response(spec_msgs):
    assert verify_response(spec_msgs, spec_msgs.m4, spec_msgs.m5)
    assert not verify_response(spec_msgs, spec_msgs.m4, bytes(16))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"uid": bytes(14)},
        {"counter": 1 << 28},
        {"counter": -1},
        {"new_key": bytes(15)},
    ],
)
def test_rejects_bad_input(kwargs):
    args = dict(uid=UID, key_id=4, auth_id=1, auth_key=MASTER_KEY, new_key=NEW_KEY, counter=1)
    args.update(kwargs)
    with pytest.raises(ValueError):
        build_key_update(**args)
