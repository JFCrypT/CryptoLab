# Getting started

## Requirements

- Linux;
- Python 3.12 or newer;
- uv.

## Install the development environment

```bash
uv sync
```

## Run the CLI

```bash
uv run cryptolab --help
```

## Try Euclidean division

```bash
uv run cryptolab integer divide -17 5 --explain
```

CryptoLab uses the remainder convention:

\[
a=bq+r, \qquad 0\le r<|b|.
\]

Therefore:

\[
-17=5(-4)+3.
\]

## Run the tests

```bash
uv run pytest
```
