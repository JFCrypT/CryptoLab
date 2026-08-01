from __future__ import annotations

import pytest

from cryptolab.classical.alphabet import UnknownSymbolPolicy, load_builtin_alphabet
from cryptolab.classical.polybius import (
    build_polybius_grid,
    polybius_decrypt,
    polybius_encrypt,
)
from cryptolab.exceptions import InputValidationError

LATIN = load_builtin_alphabet("latin-upper")
SPANISH = load_builtin_alphabet("spanish-upper")


def test_default_and_rectangular_polybius_grids() -> None:
    grid = build_polybius_grid(LATIN)
    assert (grid.rows, grid.columns) == (6, 6)
    assert grid.cells[0] == "A"
    assert grid.cells[25] == "Z"
    assert grid.cells[-1] is None

    rectangular = build_polybius_grid(LATIN, 3, 9)
    assert (rectangular.rows, rectangular.columns) == (3, 9)
    assert rectangular.cells[-1] is None


def test_polybius_round_trip_with_preserved_space() -> None:
    encrypted = polybius_encrypt("ABC D", SPANISH)
    assert encrypted.output_text == "11 12 13 u+20 14"
    decrypted = polybius_decrypt(encrypted.output_text, SPANISH)
    assert decrypted.output_text == "ABC D"


def test_polybius_reject_policy_and_invalid_coordinates() -> None:
    with pytest.raises(InputValidationError, match="position 1"):
        polybius_encrypt("A A", LATIN, UnknownSymbolPolicy.REJECT)
    with pytest.raises(InputValidationError, match="outside"):
        polybius_decrypt("99", LATIN)
    with pytest.raises(InputValidationError, match="empty grid cell"):
        polybius_decrypt("66", LATIN)
    with pytest.raises(InputValidationError, match="expected ROWCOLUMN"):
        polybius_decrypt("abc", LATIN)
    with pytest.raises(InputValidationError, match="forbidden"):
        polybius_decrypt("u+20", LATIN, UnknownSymbolPolicy.REJECT)
    with pytest.raises(InputValidationError, match="Invalid preserved"):
        polybius_decrypt("u+xyz", LATIN)
    with pytest.raises(InputValidationError, match="Invalid preserved"):
        polybius_decrypt("u+d800", LATIN)


def test_polybius_dimension_validation() -> None:
    with pytest.raises(InputValidationError, match="supplied together"):
        build_polybius_grid(LATIN, rows=5)
    with pytest.raises(InputValidationError, match="rows"):
        build_polybius_grid(LATIN, 1, 9)
    with pytest.raises(InputValidationError, match="columns"):
        build_polybius_grid(LATIN, 3, 10)
    with pytest.raises(InputValidationError, match="cannot contain"):
        build_polybius_grid(LATIN, 2, 2)
