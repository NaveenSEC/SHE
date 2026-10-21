from she_memory_update.cli import main

from .conftest import UID


def test_default_run_matches_spec(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "M5 820d8d95dc11b4668878160cb2a4e23e" in out
    assert "verified" in out


def test_no_emulate(capsys):
    assert main(["--no-emulate"]) == 0
    assert "Emulator" not in capsys.readouterr().out


def test_ram_key_with_secret_key(capsys):
    assert main(["--key-id", "RAM_KEY", "--auth-id", "SECRET_KEY", "--counter", "0"]) == 0


def test_rejected_request(capsys):
    assert main(["--key-id", "SECRET_KEY"]) == 1
    assert "ERC_KEY_INVALID" in capsys.readouterr().out


def test_numeric_slot_and_flags(capsys):
    assert main(["--key-id", "0x5", "--uid", UID.hex(), "--write-protection", "--key-usage"]) == 0
