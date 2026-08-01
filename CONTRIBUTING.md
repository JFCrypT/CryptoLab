# Contributing to CryptoLab

CryptoLab accepts contributions that preserve its educational, mathematically rigorous,
limited, and reproducible scope.

## Language

All repository content must be written in English. This includes code, identifiers,
comments, docstrings, tests, CLI output, documentation, commits, issues, and pull requests.
Alphabet symbols are data and may contain non-English characters.

## Development setup

```bash
uv sync
# Required only when working from a source archive rather than a clone.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || git init -b main
uv run pre-commit install
```

## Required checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run mkdocs build --strict
uv build --no-sources
```

## Scope control

A contribution must not silently add:

- a new attack laboratory;
- a new cryptographic primitive;
- a second primary cryptographic library;
- a web, desktop, network, cloud, database, AI, or hardware subsystem;
- an alternative mathematical, encoding, LFSR, padding, or byte-order convention.

Scope changes require explicit approval and documentation.

## Implementation rules

- Educational modules must prioritize readable mathematics and structured traces.
- Modern primitives must use the approved established library.
- CLI modules must remain thin adapters.
- Domain functions must not print or depend on Typer or Rich.
- Tests must validate mathematical identities, edge cases, invalid inputs, and published
  vectors where applicable.
- New dependencies require a documented justification.

## Commit messages

Use clear English commit messages. Recommended prefixes include `feat`, `fix`, `docs`,
`test`, `refactor`, `build`, and `ci`.
