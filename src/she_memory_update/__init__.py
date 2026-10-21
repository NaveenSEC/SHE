"""SHE (Secure Hardware Extension) memory update protocol: host side and emulator."""

from .emulator import SheEmulator, SheError
from .protocol import KeyFlags, KeySlot, KeyUpdateMessages, build_key_update, verify_response

__all__ = [
    "KeyFlags",
    "KeySlot",
    "KeyUpdateMessages",
    "SheEmulator",
    "SheError",
    "build_key_update",
    "verify_response",
]

__version__ = "1.0.0"
