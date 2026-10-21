"""SHE cryptographic primitives: AES-128 ECB/CBC, CMAC and the Miyaguchi-Preneel KDF.

The AES block cipher comes from the ``cryptography`` package; the modes, CMAC
and the Miyaguchi-Preneel compression are implemented here so the SHE
construction stays explicit and easy to audit.

Notation used in the comments:
    E_K(x)   AES-128 encryption of the 16-byte block x with key K
    D_K(x)   AES-128 decryption of the 16-byte block x with key K
    a ^ b    bytewise XOR
    a | b    concatenation
"""

from __future__ import annotations  # allow "list[bytes]" style type hints on Python 3.10

# AES block cipher primitive (we only use it one 16-byte block at a time).
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size in bytes (128 bits); also the AES-128 key size

# KDF constants from the SHE specification (section 7.3).
# Layout: 01 | 01 (ENC) or 02 (MAC) | "SHE" (53 48 45) | 00 | 80 00..00 (padding) | B0 (= 176-bit length)
KEY_UPDATE_ENC_C = bytes.fromhex("010153484500800000000000000000B0")  # used to derive encryption keys K1, K3
KEY_UPDATE_MAC_C = bytes.fromhex("010253484500800000000000000000B0")  # used to derive MAC keys K2, K4


def _check_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:  # AES-128 needs exactly 16 key bytes
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")  # reject any other size


def xor(a: bytes, b: bytes) -> bytes:
    """Return a ^ b for two equal-length byte strings."""
    if len(a) != len(b):  # XOR is only defined here for equal lengths
        raise ValueError("xor operands must have equal length")  # catch programming mistakes early
    return bytes(x ^ y for x, y in zip(a, b))  # XOR byte by byte: out[i] = a[i] ^ b[i]


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """E_K(block): encrypt exactly one 16-byte block."""
    _check_key(key)  # key must be 16 bytes
    if len(block) != BLOCK_SIZE:  # input must be exactly one block
        raise ValueError("block must be 16 bytes")  # anything else is a caller error
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # raw AES (ECB on a single block = plain AES)
    return enc.update(block) + enc.finalize()  # ciphertext = E_K(block)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    """D_K(block): decrypt exactly one 16-byte block."""
    _check_key(key)  # key must be 16 bytes
    if len(block) != BLOCK_SIZE:  # input must be exactly one block
        raise ValueError("block must be 16 bytes")  # anything else is a caller error
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # raw AES inverse
    return dec.update(block) + dec.finalize()  # plaintext = D_K(block)


def _blocks(data: bytes) -> list[bytes]:
    """Split data into 16-byte blocks: data = x_1 | x_2 | ... | x_n."""
    if len(data) % BLOCK_SIZE:  # modes here do not pad, so length must be a whole number of blocks
        raise ValueError("data length must be a multiple of 16 bytes")  # refuse partial blocks
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]  # slice every 16 bytes


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """ECB encryption: C_i = E_K(P_i) for every block independently."""
    return b"".join(aes_encrypt_block(key, b) for b in _blocks(data))  # encrypt each block, then join


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """ECB decryption: P_i = D_K(C_i) for every block independently."""
    return b"".join(aes_decrypt_block(key, b) for b in _blocks(data))  # decrypt each block, then join


def cbc_encrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    """CBC encryption: C_0 = IV, C_i = E_K(P_i ^ C_(i-1)). SHE uses IV = 0."""
    out, prev = [], iv  # prev holds C_(i-1); starts as the IV (C_0)
    for block in _blocks(data):  # walk the plaintext blocks P_1 .. P_n
        prev = aes_encrypt_block(key, xor(block, prev))  # C_i = E_K(P_i ^ C_(i-1))
        out.append(prev)  # collect C_i
    return b"".join(out)  # ciphertext = C_1 | C_2 | ... | C_n


def cbc_decrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    """CBC decryption: P_i = D_K(C_i) ^ C_(i-1), C_0 = IV."""
    out, prev = [], iv  # prev holds C_(i-1); starts as the IV
    for block in _blocks(data):  # walk the ciphertext blocks C_1 .. C_n
        out.append(xor(aes_decrypt_block(key, block), prev))  # P_i = D_K(C_i) ^ C_(i-1)
        prev = block  # this ciphertext block chains into the next one
    return b"".join(out)  # plaintext = P_1 | P_2 | ... | P_n


def _left_shift(block: bytes) -> bytes:
    """Shift a 128-bit value left by one bit (the top bit falls off)."""
    value = (int.from_bytes(block, "big") << 1) & ((1 << 128) - 1)  # x << 1, kept to 128 bits
    return value.to_bytes(BLOCK_SIZE, "big")  # back to 16 bytes, big endian


def _cmac_subkeys(key: bytes) -> tuple[bytes, bytes]:
    """CMAC subkeys (SP 800-38B):  L = E_K(0);  K1' = dbl(L);  K2' = dbl(K1')

    dbl(x) = x << 1, then XOR 0x87 into the last byte if the top bit of x was 1
    (multiplication by 2 in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1).
    """
    rb = bytes(15) + b"\x87"  # R_b constant for 128-bit blocks: 0x00..0087
    l = aes_encrypt_block(key, bytes(BLOCK_SIZE))  # L = E_K(0^128)
    k1 = _left_shift(l)  # K1' = L << 1
    if l[0] & 0x80:  # if the top bit of L was 1 ...
        k1 = xor(k1, rb)  # ... K1' = (L << 1) ^ R_b
    k2 = _left_shift(k1)  # K2' = K1' << 1
    if k1[0] & 0x80:  # if the top bit of K1' was 1 ...
        k2 = xor(k2, rb)  # ... K2' = (K1' << 1) ^ R_b
    return k1, k2  # K1' is used for a full last block, K2' for a padded one


def cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC (NIST SP 800-38B / RFC 4493).

    M_n' = M_n ^ K1'               if the last block is complete
    M_n' = (M_n | 10..0) ^ K2'     otherwise (also for an empty message)
    X_0 = 0,  X_i = E_K(X_(i-1) ^ M_i),  CMAC = X_n
    """
    k1, k2 = _cmac_subkeys(key)  # derive the two CMAC subkeys from the key
    if message and len(message) % BLOCK_SIZE == 0:  # non-empty and a whole number of blocks
        blocks = _blocks(message)  # split into M_1 .. M_n
        blocks[-1] = xor(blocks[-1], k1)  # last block: M_n' = M_n ^ K1'
    else:  # partial last block (or empty message)
        padded = message + b"\x80" + bytes(BLOCK_SIZE - len(message) % BLOCK_SIZE - 1)  # append 1 bit then zeros
        blocks = _blocks(padded)  # split the padded message
        blocks[-1] = xor(blocks[-1], k2)  # last block: M_n' = pad(M_n) ^ K2'
    state = bytes(BLOCK_SIZE)  # X_0 = 0
    for block in blocks:  # CBC-MAC over all blocks
        state = aes_encrypt_block(key, xor(state, block))  # X_i = E_K(X_(i-1) ^ M_i)
    return state  # tag T = X_n (full 128 bits)


def mp_pad(message: bytes) -> bytes:
    """SHE Miyaguchi-Preneel padding: a 1 bit, zeros, then a 40-bit bit length.

    padded = message | 1 | 0...0 | len(message) in bits (40 bits),  total length a multiple of 128 bits
    """
    bit_len = len(message) * 8  # message length in bits
    padded = message + b"\x80"  # append a single 1 bit (0x80 = 1000 0000)
    while (len(padded) + 5) % BLOCK_SIZE:  # add zeros until 5 bytes are left at the end of a block
        padded += b"\x00"  # zero padding
    return padded + bit_len.to_bytes(5, "big")  # the last 40 bits hold the original length


def miyaguchi_preneel(message: bytes, pad: bool = False) -> bytes:
    """Miyaguchi-Preneel compression: H_i = E_{H_{i-1}}(x_i) ^ x_i ^ H_{i-1}, H_0 = 0."""
    data = mp_pad(message) if pad else message  # optionally apply the SHE padding first
    h = bytes(BLOCK_SIZE)  # H_0 = 0^128
    for block in _blocks(data):  # process x_1 .. x_n
        h = xor(xor(aes_encrypt_block(h, block), block), h)  # H_i = E_(H_(i-1))(x_i) ^ x_i ^ H_(i-1)
    return h  # MP(x_1 | ... | x_n) = H_n


def kdf(key: bytes, constant: bytes) -> bytes:
    """SHE key derivation: KDF(K, C) = MP(K || C).

    With two blocks this expands to:
        H_1 = E_0(K) ^ K
        KDF = E_(H_1)(C) ^ C ^ H_1
    No extra padding block is needed: C already contains the MP padding.
    """
    _check_key(key)  # K must be a 16-byte key
    return miyaguchi_preneel(key + constant)  # MP over the two blocks x_1 = K, x_2 = C
