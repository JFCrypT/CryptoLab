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
uv run cryptolab --explain integer divide -17 5
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

## Solve a Diophantine equation

```bash
uv run cryptolab --explain diophantine solve 33 17 1
```

## Solve a modular system

```bash
uv run cryptolab --explain modular crt \
  --congruence 5:7 \
  --congruence 0:6 \
  --congruence=-1:5
```
