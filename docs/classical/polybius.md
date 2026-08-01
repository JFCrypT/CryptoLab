# Polybius square

CryptoLab generalizes the Polybius square to a bounded rectangular grid while retaining the
classical row-and-column interpretation.

Conventions:

- row-major filling;
- one-based coordinates;
- rows and columns from 2 to 9;
- the smallest square grid when dimensions are omitted;
- unused trailing cells are invalid coordinates.

## Build a grid

```bash
uv run cryptolab --explain classical polybius build --alphabet spanish-upper
```

Custom dimensions must be supplied together:

```bash
uv run cryptolab classical polybius build --rows 3 --columns 9
```

## Canonical ciphertext format

A transformed symbol is represented by a two-digit `ROWCOLUMN` token. Tokens are separated
by spaces.

A preserved unknown symbol is represented as `u+HEX`, where `HEX` is its Unicode code
point. For example, a preserved space is `u+20`.

```bash
uv run cryptolab classical polybius encrypt "ABC D"
# 11 12 13 u+20 14

uv run cryptolab classical polybius decrypt "11 12 13 u+20 14"
# ABC D
```

This explicit token format avoids ambiguity between coordinate separators and preserved
plaintext characters.

CryptoLab validates malformed tokens, out-of-range coordinates, and coordinates that refer
to unused cells.

!!! warning
    Polybius is an educational classical construction and does not provide modern security.
