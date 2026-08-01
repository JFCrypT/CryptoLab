from __future__ import annotations

from json import dumps, loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_classical() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "classical" in result.stdout


def test_caesar_encrypt_decrypt_and_json() -> None:
    encrypted = runner.invoke(
        app,
        ["classical", "caesar", "encrypt", "PARABOLOIDE", "9", "--alphabet", "spanish-upper"],
    )
    assert encrypted.exit_code == 0
    ciphertext = encrypted.stdout.strip()

    decrypted = runner.invoke(
        app,
        ["classical", "caesar", "decrypt", ciphertext, "9", "--alphabet", "spanish-upper"],
    )
    assert decrypted.exit_code == 0
    assert decrypted.stdout.strip() == "PARABOLOIDE"

    payload_result = runner.invoke(
        app,
        ["--format", "json", "classical", "caesar", "encrypt", "ABC", "3"],
    )
    assert payload_result.exit_code == 0
    assert loads(payload_result.stdout)["result"]["output"] == "DEF"


def test_caesar_accepts_negative_positional_shift_and_unknown_alias() -> None:
    negative = runner.invoke(app, ["classical", "caesar", "encrypt", "HELLO", "-3"])
    assert negative.exit_code == 0
    assert negative.stdout.strip() == "EBIIL"

    preserved = runner.invoke(
        app,
        [
            "classical",
            "caesar",
            "encrypt",
            "HELLO, WORLD!",
            "3",
            "--unknown-symbols",
            "preserve",
        ],
    )
    assert preserved.exit_code == 0
    assert preserved.stdout.strip() == "KHOOR, ZRUOG!"


def test_caesar_table_candidates_and_frequency() -> None:
    table = runner.invoke(app, ["classical", "caesar", "table", "3"])
    assert table.exit_code == 0
    assert "Output index" in table.stdout

    candidates = runner.invoke(app, ["classical", "caesar", "candidates", "KHOOR"])
    assert candidates.exit_code == 0
    assert "HELLO" in candidates.stdout

    frequency = runner.invoke(app, ["classical", "caesar", "frequency", "ABRACADABRA!"])
    assert frequency.exit_code == 0
    assert "Most frequent alphabet symbol(s): A" in frequency.stdout


def test_vigenere_round_trip() -> None:
    encrypted = runner.invoke(
        app,
        ["classical", "vigenere", "encrypt", "ATTACKATDAWN", "LEMON"],
    )
    assert encrypted.exit_code == 0
    assert encrypted.stdout.strip() == "LXFOPVEFRNHR"

    decrypted = runner.invoke(
        app,
        ["classical", "vigenere", "decrypt", "LXFOPVEFRNHR", "LEMON"],
    )
    assert decrypted.exit_code == 0
    assert decrypted.stdout.strip() == "ATTACKATDAWN"


def test_polybius_build_and_round_trip() -> None:
    grid = runner.invoke(app, ["classical", "polybius", "build"])
    assert grid.exit_code == 0
    assert "Row\\Col" in grid.stdout

    encrypted = runner.invoke(app, ["classical", "polybius", "encrypt", "ABC D"])
    assert encrypted.exit_code == 0
    assert encrypted.stdout.strip() == "11 12 13 u+20 14"

    decrypted = runner.invoke(
        app,
        ["classical", "polybius", "decrypt", "11 12 13 u+20 14"],
    )
    assert decrypted.exit_code == 0
    assert decrypted.stdout.strip() == "ABC D"


def test_custom_alphabet_and_mutually_exclusive_options(tmp_path) -> None:
    path = tmp_path / "binary.json"
    path.write_text(dumps({"name": "binary", "symbols": ["0", "1"]}), encoding="utf-8")
    result = runner.invoke(
        app,
        ["classical", "caesar", "encrypt", "010", "1", "--alphabet-file", str(path)],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "101"

    invalid = runner.invoke(
        app,
        [
            "classical",
            "caesar",
            "encrypt",
            "ABC",
            "1",
            "--alphabet",
            "latin-upper",
            "--alphabet-file",
            str(path),
        ],
    )
    assert invalid.exit_code == 3
    assert "either --alphabet or --alphabet-file" in invalid.stderr


def test_reject_unknown_symbol_exit_code() -> None:
    result = runner.invoke(
        app,
        [
            "classical",
            "caesar",
            "encrypt",
            "A A",
            "1",
            "--unknown-symbols",
            "reject",
        ],
    )
    assert result.exit_code == 3
    assert "not in alphabet" in result.stderr


def test_vigenere_alignment_command() -> None:
    human = runner.invoke(
        app,
        ["classical", "vigenere", "align", "ATTACK AT DAWN", "LEMON"],
    )
    assert human.exit_code == 0
    assert "Repeated key: LEMON" in human.stdout
    assert "Key pos" in human.stdout

    payload = runner.invoke(
        app,
        [
            "--format",
            "json",
            "classical",
            "vigenere",
            "align",
            "A A",
            "BC",
        ],
    )
    assert payload.exit_code == 0
    result = loads(payload.stdout)["result"]
    assert result["resulting_ciphertext"] == "B C"
    assert result["repeated_key_alignment"][1]["key_position"] is None
