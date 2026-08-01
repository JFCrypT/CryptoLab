from __future__ import annotations

from json import dumps

import pytest

from cryptolab.classical.alphabet import (
    Alphabet,
    builtin_alphabet_names,
    load_alphabet_file,
    load_builtin_alphabet,
)
from cryptolab.exceptions import InputValidationError, ResourceLimitError


def test_builtin_alphabets() -> None:
    assert builtin_alphabet_names() == ("latin-upper", "spanish-upper")
    latin = load_builtin_alphabet("latin-upper")
    spanish = load_builtin_alphabet("spanish-upper")
    assert len(latin.symbols) == 26
    assert len(spanish.symbols) == 27
    assert spanish.symbols[14] == "Ñ"


def test_custom_alphabet_file(tmp_path) -> None:
    path = tmp_path / "alphabet.json"
    path.write_text(dumps({"name": "binary", "symbols": ["0", "1"]}), encoding="utf-8")
    alphabet = load_alphabet_file(path)
    assert alphabet.symbols == ("0", "1")


def test_alphabet_validation_errors(tmp_path) -> None:
    with pytest.raises(InputValidationError, match="unique"):
        Alphabet("duplicate", ("A", "A"))
    with pytest.raises(InputValidationError, match="one Unicode"):
        Alphabet("tokens", ("AA", "B"))
    with pytest.raises(InputValidationError, match="at least"):
        Alphabet("small", ("A",))
    with pytest.raises(ResourceLimitError):
        Alphabet("large", tuple(chr(0x1000 + value) for value in range(257)))
    with pytest.raises(InputValidationError, match="Unknown built-in"):
        load_builtin_alphabet("missing")

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(InputValidationError, match="valid JSON"):
        load_alphabet_file(invalid_json)

    missing = tmp_path / "missing.json"
    with pytest.raises(InputValidationError, match="Unable to read"):
        load_alphabet_file(missing)


def test_alphabet_payload_validation(tmp_path) -> None:
    path = tmp_path / "payload.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(InputValidationError, match="JSON object"):
        load_alphabet_file(path)

    path.write_text(dumps({"name": 1, "symbols": ["A", "B"]}), encoding="utf-8")
    with pytest.raises(InputValidationError, match="must contain"):
        load_alphabet_file(path)

    path.write_text(dumps({"name": "bad", "symbols": ["A", 2]}), encoding="utf-8")
    with pytest.raises(InputValidationError, match="must be strings"):
        load_alphabet_file(path)
