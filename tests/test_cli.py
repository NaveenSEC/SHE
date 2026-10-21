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


def test_explain_shows_derived_keys(capsys):
    assert main(["--explain", "--no-emulate"]) == 0
    out = capsys.readouterr().out
    assert "K1 = KDF(K_AuthID, KEY_UPDATE_ENC_C) = 118a46447a770d87828a69c222e2d17e" in out
    assert "K4 = KDF(KEY_new,  KEY_UPDATE_MAC_C) = ec9386fefaa1c598246144343de5f26a" in out
    assert "plaintext block 1 = 00000010000000000000000000000000" in out
    assert "counter block     = 00000018000000000000000000000000" in out
