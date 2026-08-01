"""Educational Polybius grids with explicit coordinate-token validation."""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

from cryptolab.classical.alphabet import Alphabet, UnknownSymbolPolicy
from cryptolab.exceptions import InputValidationError
from cryptolab.limits import MAX_POLYBIUS_DIMENSION, MIN_POLYBIUS_DIMENSION

UNICODE_ESCAPE_PREFIX = "u+"
COORDINATE_TOKEN_LENGTH = 2
MAX_UNICODE_CODE_POINT = 0x10FFFF
SURROGATE_START = 0xD800
SURROGATE_END = 0xDFFF


@dataclass(frozen=True, slots=True)
class PolybiusGrid:
    """A row-major, one-based Polybius grid."""

    alphabet_name: str
    rows: int
    columns: int
    cells: tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class PolybiusStep:
    """One Polybius encoding or decoding step."""

    position: int
    input_value: str
    output_value: str
    row: int | None
    column: int | None
    transformed: bool


@dataclass(frozen=True, slots=True)
class PolybiusResult:
    """Polybius encryption or decryption result."""

    operation: str
    input_text: str
    output_text: str
    alphabet_name: str
    rows: int
    columns: int
    unknown_policy: UnknownSymbolPolicy
    steps: tuple[PolybiusStep, ...]


def _default_dimension(symbol_count: int) -> int:
    root = isqrt(symbol_count)
    return root if root * root == symbol_count else root + 1


def build_polybius_grid(
    alphabet: Alphabet,
    rows: int | None = None,
    columns: int | None = None,
) -> PolybiusGrid:
    """Build a row-major grid, using the smallest square when dimensions are omitted."""

    if (rows is None) != (columns is None):
        raise InputValidationError("Polybius rows and columns must be supplied together.")
    if rows is None or columns is None:
        rows = columns = _default_dimension(len(alphabet.symbols))
    if not MIN_POLYBIUS_DIMENSION <= rows <= MAX_POLYBIUS_DIMENSION:
        raise InputValidationError(
            f"Polybius rows must be between {MIN_POLYBIUS_DIMENSION} and {MAX_POLYBIUS_DIMENSION}."
        )
    if not MIN_POLYBIUS_DIMENSION <= columns <= MAX_POLYBIUS_DIMENSION:
        raise InputValidationError(
            f"Polybius columns must be between {MIN_POLYBIUS_DIMENSION} and "
            f"{MAX_POLYBIUS_DIMENSION}."
        )
    capacity = rows * columns
    if capacity < len(alphabet.symbols):
        raise InputValidationError(
            f"A {rows}x{columns} grid cannot contain {len(alphabet.symbols)} symbols."
        )
    cells: tuple[str | None, ...] = alphabet.symbols + (None,) * (capacity - len(alphabet.symbols))
    return PolybiusGrid(
        alphabet_name=alphabet.name,
        rows=rows,
        columns=columns,
        cells=cells,
    )


def _coordinate(index: int, columns: int) -> tuple[int, int]:
    return index // columns + 1, index % columns + 1


def _unicode_token(symbol: str) -> str:
    return f"{UNICODE_ESCAPE_PREFIX}{ord(symbol):x}"


def polybius_encrypt(
    text: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
    *,
    rows: int | None = None,
    columns: int | None = None,
) -> PolybiusResult:
    """Encode text as a space-separated stream of coordinates and Unicode escape tokens."""

    grid = build_polybius_grid(alphabet, rows, columns)
    index_map = alphabet.index_map()
    output_tokens: list[str] = []
    steps: list[PolybiusStep] = []

    for position, symbol in enumerate(text):
        index = index_map.get(symbol)
        if index is None:
            if unknown_policy is UnknownSymbolPolicy.REJECT:
                raise InputValidationError(
                    f"Symbol {symbol!r} at position {position} is not in alphabet "
                    f"'{alphabet.name}'."
                )
            token = _unicode_token(symbol)
            output_tokens.append(token)
            steps.append(
                PolybiusStep(
                    position=position,
                    input_value=symbol,
                    output_value=token,
                    row=None,
                    column=None,
                    transformed=False,
                )
            )
            continue

        row, column = _coordinate(index, grid.columns)
        token = f"{row}{column}"
        output_tokens.append(token)
        steps.append(
            PolybiusStep(
                position=position,
                input_value=symbol,
                output_value=token,
                row=row,
                column=column,
                transformed=True,
            )
        )

    return PolybiusResult(
        operation="encrypt",
        input_text=text,
        output_text=" ".join(output_tokens),
        alphabet_name=alphabet.name,
        rows=grid.rows,
        columns=grid.columns,
        unknown_policy=unknown_policy,
        steps=tuple(steps),
    )


def _decode_unicode_token(token: str) -> str:
    try:
        code_point = int(token[len(UNICODE_ESCAPE_PREFIX) :], 16)
    except ValueError as error:
        raise InputValidationError(f"Invalid preserved Unicode token: {token!r}.") from error
    if (
        code_point < 0
        or code_point > MAX_UNICODE_CODE_POINT
        or SURROGATE_START <= code_point <= SURROGATE_END
    ):
        raise InputValidationError(f"Invalid preserved Unicode token: {token!r}.")
    return chr(code_point)


def polybius_decrypt(
    ciphertext: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
    *,
    rows: int | None = None,
    columns: int | None = None,
) -> PolybiusResult:
    """Decode a canonical space-separated Polybius token stream."""

    grid = build_polybius_grid(alphabet, rows, columns)
    tokens = ciphertext.split()
    output_symbols: list[str] = []
    steps: list[PolybiusStep] = []

    for position, token in enumerate(tokens):
        if token.lower().startswith(UNICODE_ESCAPE_PREFIX):
            if unknown_policy is UnknownSymbolPolicy.REJECT:
                raise InputValidationError(
                    "Preserved Unicode tokens are forbidden when unknown-symbol policy is reject."
                )
            decoded_symbol = _decode_unicode_token(token.lower())
            output_symbols.append(decoded_symbol)
            steps.append(
                PolybiusStep(
                    position=position,
                    input_value=token,
                    output_value=decoded_symbol,
                    row=None,
                    column=None,
                    transformed=False,
                )
            )
            continue

        if len(token) != COORDINATE_TOKEN_LENGTH or not token.isdecimal():
            raise InputValidationError(
                f"Invalid Polybius token {token!r}; expected ROWCOLUMN or u+HEX."
            )
        row = int(token[0])
        column = int(token[1])
        if not 1 <= row <= grid.rows or not 1 <= column <= grid.columns:
            raise InputValidationError(
                f"Coordinate {token!r} lies outside the {grid.rows}x{grid.columns} grid."
            )
        index = (row - 1) * grid.columns + (column - 1)
        cell = grid.cells[index]
        if cell is None:
            raise InputValidationError(f"Coordinate {token!r} identifies an empty grid cell.")
        output_symbols.append(cell)
        steps.append(
            PolybiusStep(
                position=position,
                input_value=token,
                output_value=cell,
                row=row,
                column=column,
                transformed=True,
            )
        )

    return PolybiusResult(
        operation="decrypt",
        input_text=ciphertext,
        output_text="".join(output_symbols),
        alphabet_name=alphabet.name,
        rows=grid.rows,
        columns=grid.columns,
        unknown_policy=unknown_policy,
        steps=tuple(steps),
    )
