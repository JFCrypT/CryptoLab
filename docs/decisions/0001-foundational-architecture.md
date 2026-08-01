# ADR 0001: Foundational architecture

- **Status:** accepted
- **Decision date:** 2026-08-01

## Decision

CryptoLab uses Python 3.12 or newer, a `src` package layout, uv and `uv_build`, Typer and
Rich for the CLI and presentation layer, pytest and selected Hypothesis tests, Ruff, mypy,
pre-commit, and MkDocs with Material.

The architecture separates domain modules, library-backed wrappers, application
orchestration, rendering, and the CLI. Domain code does not print and does not depend on
Typer or Rich.

The repository grows with implemented functionality and must not contain empty packages,
placeholder modules, speculative abstractions, or parallel educational and secure trees.

## Rationale

The structure keeps mathematical and cryptographic logic independently testable, prevents
CLI concerns from contaminating domain functions, and supports human, JSON, and LaTeX
output without duplicating algorithms.

## Consequences

Every new feature requires a domain result model, tests, documentation, and a thin CLI
adapter. Modern primitives require the approved cryptographic library rather than manual
reimplementation.
