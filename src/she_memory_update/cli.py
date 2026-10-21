"""Command line interface: generate M1..M5 and optionally run them through the emulator."""

from __future__ import annotations  # allow "list[str] | None" type hints on Python 3.10

import argparse  # command line parsing
import sys  # sys.exit with the program's return code

from .crypto import KEY_UPDATE_ENC_C, KEY_UPDATE_MAC_C, kdf  # used by --explain to show K1..K4
from .emulator import SheEmulator, SheError  # software SHE module to test the request against
from .protocol import KeyFlags, KeySlot, KeyUpdateMessages, build_key_update, verify_response


def _hex_bytes(size: int):
    """Return an argparse type that parses a hex string of exactly ``size`` bytes."""

    def parse(text: str) -> bytes:
        try:
            value = bytes.fromhex(text.replace(" ", ""))  # "00 11 22" or "001122" -> b"\x00\x11\x22"
        except ValueError as exc:  # not hex digits, or an odd number of them
            raise argparse.ArgumentTypeError(f"not valid hex: {text}") from exc
        if len(value) != size:  # e.g. a UID must be exactly 15 bytes
            raise argparse.ArgumentTypeError(f"expected {size} bytes, got {len(value)}")
        return value  # parsed bytes

    return parse  # argparse calls this for the option value


def _slot(text: str) -> int:
    """Parse a key slot given by name (KEY_1, ram_key) or by number (4, 0x4)."""
    try:
        return KeySlot[text.upper()]  # by name, case-insensitive
    except KeyError:  # not a slot name ...
        try:
            return KeySlot(int(text, 0))  # ... so try a number; base 0 accepts "4", "0x4", "0b100"
        except ValueError as exc:  # neither a name nor a valid slot number
            raise argparse.ArgumentTypeError(f"unknown key slot: {text}") from exc


def explain(args: argparse.Namespace, flags: KeyFlags, msgs: KeyUpdateMessages) -> None:
    """Print every intermediate value used to form M1..M5 (see docs/PROTOCOL.md)."""
    f_id = flags.to_bits()  # F_ID = WP<<4 | BP<<3 | DP<<2 | KU<<1 | WC
    m2_block1 = (args.counter << 100 | f_id << 95).to_bytes(16, "big")  # C_ID(28) | F_ID(5) | 0(95)
    m4_block = (args.counter << 100 | 1 << 99).to_bytes(16, "big")  # C_ID(28) | 1 | 0(99)
    print("Inputs:")
    print(f"  UID      {args.uid.hex()}")  # 120-bit module UID
    print(f"  ID       {args.key_id:#x} ({KeySlot(args.key_id).name})")  # slot to write
    print(f"  AuthID   {args.auth_id:#x} ({KeySlot(args.auth_id).name})")  # authorizing slot
    print(f"  K_AuthID {args.auth_key.hex()}")  # authorizing key value
    print(f"  KEY_new  {args.new_key.hex()}")  # new key value
    print(f"  C_ID     {args.counter:#x}")  # new 28-bit counter
    print(f"  F_ID     {f_id:05b} (WP BP DP KU WC)")  # flags as 5 binary digits
    print("Derived keys, KDF(K, C) = Miyaguchi-Preneel(K | C):")
    print(f"  K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) = {kdf(args.auth_key, KEY_UPDATE_ENC_C).hex()}")  # encrypts M2
    print(f"  K2 = KDF(K_AuthID, KEY_UPDATE_MAC_C) = {kdf(args.auth_key, KEY_UPDATE_MAC_C).hex()}")  # MAC key for M3
    print(f"  K3 = KDF(KEY_new,  KEY_UPDATE_ENC_C) = {kdf(args.new_key, KEY_UPDATE_ENC_C).hex()}")  # encrypts M4 block
    print(f"  K4 = KDF(KEY_new,  KEY_UPDATE_MAC_C) = {kdf(args.new_key, KEY_UPDATE_MAC_C).hex()}")  # MAC key for M5
    print("Message formation:")
    print("  M1 = UID | ID | AuthID")
    print(f"     last byte = (ID << 4) | AuthID = {msgs.m1[15]:02x}")  # e.g. KEY_1 (4) by MASTER (1) -> 41
    print("  M2 = ENC_CBC,K1,IV=0( C_ID(28) | F_ID(5) | 0(95) | KEY_new )")
    print(f"     plaintext block 1 = {m2_block1.hex()}")  # counter + flags block
    print(f"     plaintext block 2 = {args.new_key.hex()}")  # the new key itself
    print("  M3 = CMAC,K2( M1 | M2 )")
    print("  M4 = UID | ID | AuthID | ENC_ECB,K3( C_ID(28) | 1 | 0(99) )")
    print(f"     counter block     = {m4_block.hex()}")  # before encryption
    print(f"     encrypted block   = {msgs.m4[16:].hex()}")  # E_K3(counter block) = second half of M4
    print("  M5 = CMAC,K4( M4 )")
    print()  # blank line before the message listing


def build_parser() -> argparse.ArgumentParser:
    """Define the command line options. Defaults reproduce the SHE specification example."""
    p = argparse.ArgumentParser(
        prog="she-update",
        description="Build SHE CMD_LOAD_KEY messages M1..M5 and verify them against an emulated SHE module.",
    )
    p.add_argument("--uid", type=_hex_bytes(15), default=bytes(14) + b"\x01", help="15-byte UID (hex)")  # 00..01
    p.add_argument("--key-id", type=_slot, default=KeySlot.KEY_1, help="slot to update, e.g. KEY_1 or 0x4")
    p.add_argument("--auth-id", type=_slot, default=KeySlot.MASTER_ECU_KEY, help="authorizing slot")
    p.add_argument("--auth-key", type=_hex_bytes(16), default=bytes(range(16)), help="authorizing key (hex)")  # 0001..0f
    p.add_argument("--new-key", type=_hex_bytes(16), default=bytes(range(15, -1, -1)), help="new key (hex)")  # 0f0e..00
    p.add_argument("--counter", type=lambda s: int(s, 0), default=1, help="new 28-bit counter")  # decimal or 0x..
    p.add_argument("--write-protection", action="store_true")  # F_ID bit 4
    p.add_argument("--boot-protection", action="store_true")  # F_ID bit 3
    p.add_argument("--debugger-protection", action="store_true")  # F_ID bit 2
    p.add_argument("--key-usage", action="store_true")  # F_ID bit 1
    p.add_argument("--wildcard", action="store_true")  # F_ID bit 0
    p.add_argument("--no-emulate", action="store_true", help="only print the messages for a real ECU")
    p.add_argument("--explain", action="store_true", help="show the derived keys and how each message is formed")
    return p  # the configured parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns 0 on success, 1 if the emulator rejects or the response mismatches."""
    args = build_parser().parse_args(argv)  # parse sys.argv (or the given list, used by the tests)
    flags = KeyFlags(  # collect the five flag options into F_ID
        write_protection=args.write_protection,
        boot_protection=args.boot_protection,
        debugger_protection=args.debugger_protection,
        key_usage=args.key_usage,
        wildcard=args.wildcard,
    )
    # Host side: compute the request M1..M3 and the expected answer M4, M5.
    msgs = build_key_update(args.uid, args.key_id, args.auth_id, args.auth_key, args.new_key, args.counter, flags)

    if args.explain:  # optional: show K1..K4 and the plaintext blocks
        explain(args, flags, msgs)

    print("Request (send to the SHE module):")
    print(f"  M1 {msgs.m1.hex()}")  # 16 bytes
    print(f"  M2 {msgs.m2.hex()}")  # 32 bytes
    print(f"  M3 {msgs.m3.hex()}")  # 16 bytes
    print("Expected response:")
    print(f"  M4 {msgs.m4.hex()}")  # 32 bytes
    print(f"  M5 {msgs.m5.hex()}")  # 16 bytes

    if args.no_emulate:  # real-ECU mode: just print the messages
        return 0

    # Build an emulated module that already holds the authorizing key.
    # SECRET_KEY is a factory key, so it goes in through the constructor; other slots via provision().
    she = SheEmulator(args.uid, secret_key=args.auth_key if args.auth_id == KeySlot.SECRET_KEY else None)
    if args.auth_id != KeySlot.SECRET_KEY:
        she.provision(args.auth_id, args.auth_key)  # pre-load K_AuthID into slot AuthID
    try:
        m4, m5 = she.load_key(msgs.m1, msgs.m2, msgs.m3)  # send the request, get the module's M4, M5
    except SheError as exc:  # the module refused (bad slot, MAC, UID, counter, ...)
        print(f"Emulator rejected the request: {exc}")
        return 1

    ok = verify_response(msgs, m4, m5)  # the module's M4, M5 must equal the host's own computation
    print(f"Emulator response {'verified' if ok else 'MISMATCH'}: key stored in {KeySlot(args.key_id).name}")
    return 0 if ok else 1  # exit code: 0 = key confirmed stored


if __name__ == "__main__":  # allow "python cli.py"
    sys.exit(main())  # return the exit code to the shell
