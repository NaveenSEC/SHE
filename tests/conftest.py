import pytest

from she_memory_update import KeySlot, SheEmulator

UID = bytes(14) + b"\x01"
MASTER_KEY = bytes(range(16))
NEW_KEY = bytes(range(15, -1, -1))


@pytest.fixture
def she():
    emu = SheEmulator(UID)
    emu.provision(KeySlot.MASTER_ECU_KEY, MASTER_KEY)
    return emu
