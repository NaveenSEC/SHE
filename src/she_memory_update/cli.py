"""Command line interface: generate M1..M5 and optionally run them through the emulator."""

from __future__ import annotations

import argparse
import sys

from .crypto import KEY_UPDATE_ENC_C, KEY_UPDATE_MAC_C, kdf
from .emulator import SheEmulator, SheError
from .protocol import KeyFlags, KeySlot, KeyUpdateMessages, build_key_update, verify_response


def _hex_bytes(size: int):
    def parse(text: str) -> bytes:
        try:
            value = bytes.fromhex(text.replace(" ", ""))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"not valid hex: {text}") from exc
        if len(value) != size:
            raise argparse.ArgumentTypeError(f"expected {size} bytes, got {len(value)}")
        return value

    return parse


def _slot(text: str) -> int:
    try:
        return KeySlot[text.upper()]
    except KeyError:
        try:
            return KeySlot(int(text, 0))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"unknown key slot: {text}") from exc


def explain(args: argparse.Namespace, flags: KeyFlags, msgs: KeyUpdateMessages) -> None:
    """Print every intermediate value used to form M1..M5 (see docs/PROTOCOL.md)."""
    f_id = flags.to_bits()
    m2_block1 = (args.counter << 100 | f_id << 95).to_bytes(16, "big")
    m4_block = (args.counter << 100 | 1 << 99).to_bytes(16, "big")
    print("Inputs:")
    print(f"  UID      {args.uid.hex()}")
    print(f"  ID       {args.key_id:#x} ({KeySlot(args.key_id).name})")
    print(f"  AuthID   {args.auth_id:#x} ({KeySlot(args.auth_id).name})")
    print(f"  K_AuthID {args.auth_key.hex()}")
    print(f"  KEY_new  {args.new_key.hex()}")
    print(f"  C_ID     {args.counter:#x}")
    print(f"  F_ID     {f_id:05b} (WP BP DP KU WC)")
    print("Derived keys, KDF(K, C) = Miyaguchi-Preneel(K | C):")
    print(f"  K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) = {kdf(args.auth_key, KEY_UPDATE_ENC_C).hex()}")
    print(f"  K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) = {kdf(args.auth_key, KEY_UPDATE_MAC_C).hex()}")
    print(f"  K3 = KDF(KEY_new,  KEY_UPDATE_ENC_C) = {kdf(args.new_key, KEY_UPDATE_ENC_C).hex()}")
    print(f"  K4 = KDF(KEY_new,  KEY_UPDATE_MAC_C) = {kdf(args.new_key, KEY_UPDATE_MAC_C).hex()}")
    print("Message formation:")
    print("  M1 = UID | ID | AuthID")
    print(f"     last byte = (ID << 4) | AuthID = {msgs.m1[15]:02x}")
    print("  M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new )")
    print(f"     plaintext block 1 = {m2_block1.hex()}")
    print(f"     plaintext block 2 = {args.new_key.hex()}")
    print("  M3 = CMAC,K2( M1 | M2 )")
    print("  M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )")
    print(f"     counter block     = {m4_block.hex()}")
    print(f"     encrypted block   = {msgs.m4[16:].hex()}")
    print("  M5 = CMAC,K4( M4 )")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="she-update",
        description="Build SHE CMD_LOAD_KEY messages M1..M5 and verify them against an emulated SHE module.",
    )
    p.add_argument("--uid", type=_hex_bytes(15), default=bytes(14) + b"\x01", help="15-byte UID (hex)")
    p.add_argument("--key-id", type=_slot, default=KeySlot.KEY_1, help="slot to update, e.g. KEY_1 or 0x4")
    p.add_argument("--auth-id", type=_slot, default=KeySlot.MASTER_ECU_KEY, help="authorizing slot")
    p.add_argument("--auth-key", type=_hex_bytes(16), default=bytes(range(16)), help="authorizing key (hex)")
    p.add_argument("--new-key", type=_hex_bytes(16), default=bytes(range(15, -1, -1)), help="new key (hex)")
    p.add_argument("--counter", type=lambda s: int(s, 0), default=1, help="new 28-bit counter")
    p.add_argument("--write-protection", action="store_true")
    p.add_argument("--boot-protection", action="store_true")
    p.add_argument("--debugger-protection", action="store_true")
    p.add_argument("--key-usage", action="store_true")
    p.add_argument("--wildcard", action="store_true")
    p.add_argument("--no-emulate", action="store_true", help="only print the messages for a real ECU")
    p.add_argument("--explain", action="store_true", help="show the derived keys and how each message is formed")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    flags = KeyFlags(
        write_protection=args.write_protection,
        boot_protection=args.boot_protection,
        debugger_protection=args.debugger_protection,
        key_usage=args.key_usage,
        wildcard=args.wildcard,
    )
    msgs = build_key_update(args.uid, args.key_id, args.auth_id, args.auth_key, args.new_key, args.counter, flags)

    if args.explain:
        explain(args, flags, msgs)

    print("Request (send to the SHE module):")
    print(f"  M1 {msgs.m1.hex()}")
    print(f"  M2 {msgs.m2.hex()}")
    print(f"  M3 {msgs.m3.hex()}")
    print("Expected response:")
    print(f"  M4 {msgs.m4.hex()}")
    print(f"  M5 {msgs.m5.hex()}")

    if args.no_emulate:
        return 0

    she = SheEmulator(args.uid, secret_key=args.auth_key if args.auth_id == KeySlot.SECRET_KEY else None)
    if args.auth_id != KeySlot.SECRET_KEY:
        she.provision(args.auth_id, args.auth_key)
    try:
        m4, m5 = she.load_key(msgs.m1, msgs.m2, msgs.m3)
    except SheError as exc:
        print(f"Emulator rejected the request: {exc}")
        return 1

    ok = verify_response(msgs, m4, m5)
    print(f"Emulator response {'verified' if ok else 'MISMATCH'}: key stored in {KeySlot(args.key_id).name}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
