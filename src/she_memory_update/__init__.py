"""SHE (Secure Hardware Extension) memory update protocol: host side and emulator."""

from .emulator import SheEmulator, SheError  # software SHE module and its error type
from .protocol import KeyFlags, KeySlot, KeyUpdateMessages, build_key_update, verify_response  # host side

__all__ = [  # names exported by "from she_memory_update import *"
    "KeyFlags",
    "KeySlot",
    "KeyUpdateMessages",
    "SheEmulator",
    "SheError",
    "build_key_update",
    "verify_response",
]

__version__ = "1.0.0"  # package version (keep in sync with pyproject.toml)
