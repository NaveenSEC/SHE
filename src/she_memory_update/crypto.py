"""SHE cryptographic primitives: AES-128 ECB/CBC, CMAC and the Miyaguchi-Preneel KDF.

The AES block cipher comes from the ``cryptography`` package; the modes, CMAC
and the Miyaguchi-Preneel compression are implemented here so the SHE
construction stays explicit and easy to audit.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16

# KDF constants from the SHE specification (section 7.3).
KEY_UPDATE_ENC_C = bytes.fromhex("010153484500800000000000000000B0")
KEY_UPDATE_MAC_C = bytes.fromhex("010253484500800000000000000000B0")


def _check_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    _check_key(key)
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    _check_key(key)
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(block) + dec.finalize()


def _blocks(data: bytes) -> list[bytes]:
    if len(data) % BLOCK_SIZE:
        raise ValueError("data length must be a multiple of 16 bytes")
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return b"".join(aes_encrypt_block(key, b) for b in _blocks(data))


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return b"".join(aes_decrypt_block(key, b) for b in _blocks(data))


def cbc_encrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    out, prev = [], iv
    for block in _blocks(data):
        prev = aes_encrypt_block(key, xor(block, prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    out, prev = [], iv
    for block in _blocks(data):
        out.append(xor(aes_decrypt_block(key, block), prev))
        prev = block
    return b"".join(out)


def _left_shift(block: bytes) -> bytes:
    value = (int.from_bytes(block, "big") << 1) & ((1 << 128) - 1)
    return value.to_bytes(BLOCK_SIZE, "big")


def _cmac_subkeys(key: bytes) -> tuple[bytes, bytes]:
    rb = bytes(15) + b"\x87"
    l = aes_encrypt_block(key, bytes(BLOCK_SIZE))
    k1 = _left_shift(l)
    if l[0] & 0x80:
        k1 = xor(k1, rb)
    k2 = _left_shift(k1)
    if k1[0] & 0x80:
        k2 = xor(k2, rb)
    return k1, k2


def cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC (NIST SP 800-38B / RFC 4493)."""
    k1, k2 = _cmac_subkeys(key)
    if message and len(message) % BLOCK_SIZE == 0:
        blocks = _blocks(message)
        blocks[-1] = xor(blocks[-1], k1)
    else:
        padded = message + b"\x80" + bytes(BLOCK_SIZE - len(message) % BLOCK_SIZE - 1)
        blocks = _blocks(padded)
        blocks[-1] = xor(blocks[-1], k2)
    state = bytes(BLOCK_SIZE)
    for block in blocks:
        state = aes_encrypt_block(key, xor(state, block))
    return state


def mp_pad(message: bytes) -> bytes:
    """SHE Miyaguchi-Preneel padding: a 1 bit, zeros, then a 40-bit bit length."""
    bit_len = len(message) * 8
    padded = message + b"\x80"
    while (len(padded) + 5) % BLOCK_SIZE:
        padded += b"\x00"
    return padded + bit_len.to_bytes(5, "big")


def miyaguchi_preneel(message: bytes, pad: bool = False) -> bytes:
    """Miyaguchi-Preneel compression: H_i = E_{H_{i-1}}(x_i) ^ x_i ^ H_{i-1}, H_0 = 0."""
    data = mp_pad(message) if pad else message
    h = bytes(BLOCK_SIZE)
    for block in _blocks(data):
        h = xor(xor(aes_encrypt_block(h, block), block), h)
    return h


def kdf(key: bytes, constant: bytes) -> bytes:
    """SHE key derivation: KDF(K, C) = MP(K || C)."""
    _check_key(key)
    return miyaguchi_preneel(key + constant)
