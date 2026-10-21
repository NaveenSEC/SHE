import pytest

from she_memory_update.crypto import (
    KEY_UPDATE_ENC_C,
    KEY_UPDATE_MAC_C,
    cbc_decrypt,
    cbc_encrypt,
    cmac,
    ecb_decrypt,
    ecb_encrypt,
    kdf,
    miyaguchi_preneel,
    mp_pad,
    xor,
)

NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)


def test_ecb_nist_sp800_38a():
    ct = ecb_encrypt(NIST_KEY, NIST_PT)
    assert ct.hex() == (
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"
    )
    assert ecb_decrypt(NIST_KEY, ct) == NIST_PT


def test_cbc_nist_sp800_38a():
    iv = bytes(range(16))
    ct = cbc_encrypt(NIST_KEY, NIST_PT, iv)
    assert ct.hex() == (
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )
    assert cbc_decrypt(NIST_KEY, ct, iv) == NIST_PT


@pytest.mark.parametrize(
    "length, tag",
    [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ],
)
def test_cmac_rfc4493(length, tag):
    assert cmac(NIST_KEY, NIST_PT[:length]).hex() == tag


def test_miyaguchi_preneel_spec_vector():
    assert miyaguchi_preneel(NIST_PT[:32], pad=True).hex() == "c7277a0dc1fb853b5f4d9cbd26be40c6"


def test_mp_pad_length():
    padded = mp_pad(bytes(32))
    assert len(padded) == 48
    assert padded[32] == 0x80
    assert int.from_bytes(padded[-5:], "big") == 256


def test_kdf_spec_vector():
    auth_key = bytes(range(16))
    assert kdf(auth_key, KEY_UPDATE_ENC_C).hex() == "118a46447a770d87828a69c222e2d17e"
    assert kdf(auth_key, KEY_UPDATE_ENC_C) != kdf(auth_key, KEY_UPDATE_MAC_C)


def test_input_validation():
    with pytest.raises(ValueError):
        ecb_encrypt(bytes(15), bytes(16))
    with pytest.raises(ValueError):
        ecb_encrypt(NIST_KEY, bytes(15))
    with pytest.raises(ValueError):
        xor(b"a", b"ab")
