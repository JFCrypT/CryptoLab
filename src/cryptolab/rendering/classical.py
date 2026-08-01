"""Presentation objects for classical cryptography modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.classical.caesar import (
    CaesarCandidate,
    CaesarResult,
    CaesarTableEntry,
    FrequencyResult,
)
from cryptolab.classical.polybius import PolybiusGrid, PolybiusResult
from cryptolab.classical.vigenere import VigenereResult
from cryptolab.rendering.common import dataclass_to_dict


@dataclass(frozen=True, slots=True)
class CaesarView:
    """Render Caesar encryption or decryption."""

    result: CaesarResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output)
        if explain:
            console.print(f"Alphabet: {self.result.alphabet_name}")
            console.print(
                f"Shift: {self.result.shift} -> {self.result.normalized_shift} "
                f"mod {self.result.alphabet_size}"
            )
            table = Table("Pos", "Input", "Index", "Output index", "Output", "Changed")
            for step in self.result.steps:
                table.add_row(
                    str(step.position),
                    repr(step.input_symbol),
                    "—" if step.input_index is None else str(step.input_index),
                    "—" if step.output_index is None else str(step.output_index),
                    repr(step.output_symbol),
                    str(step.transformed),
                )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"classical.caesar.{self.result.operation}",
            "implementation": "educational",
            "inputs": {
                "text": self.result.text,
                "shift": self.result.shift,
                "alphabet": self.result.alphabet_name,
                "unknown_policy": self.result.unknown_policy.value,
            },
            "result": {
                "output": self.result.output,
                "normalized_shift": self.result.normalized_shift,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": ["The Caesar cipher is not secure for modern use."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"E_{{{self.result.normalized_shift}}}(m_i) = "
            rf"m_i + {self.result.normalized_shift} \pmod{{{self.result.alphabet_size}}}",
            rf"\text{{Output: }}\mathtt{{{self.result.output}}}",
        ]
        if explain:
            lines.append(rf"\text{{Alphabet: {self.result.alphabet_name}}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class CaesarTableView:
    """Render a complete Caesar transformation table."""

    shift: int
    alphabet_name: str
    entries: tuple[CaesarTableEntry, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Input index", "Input", "Output index", "Output")
        for entry in self.entries:
            table.add_row(
                str(entry.input_index),
                entry.input_symbol,
                str(entry.output_index),
                entry.output_symbol,
            )
        console.print(table)
        if explain:
            console.print(f"Alphabet: {self.alphabet_name}")
            console.print(f"Normalized shift: {self.shift % len(self.entries)}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "classical.caesar.table",
            "implementation": "educational",
            "inputs": {"shift": self.shift, "alphabet": self.alphabet_name},
            "result": {"entries": [dataclass_to_dict(entry) for entry in self.entries]},
            "trace": [],
            "warnings": ["The Caesar cipher is not secure for modern use."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = " \\\\ ".join(
            f"{entry.input_symbol} & {entry.output_symbol}" for entry in self.entries
        )
        return rf"\begin{{array}}{{cc}}\text{{Input}}&\text{{Output}}\\{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class CaesarCandidatesView:
    """Render the complete Caesar key-space enumeration."""

    ciphertext: str
    alphabet_name: str
    candidates: tuple[CaesarCandidate, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Shift", "Candidate plaintext")
        for candidate in self.candidates:
            table.add_row(str(candidate.shift), candidate.plaintext)
        console.print(table)
        if explain:
            console.print(
                f"Enumerated {len(self.candidates)} keys in alphabet {self.alphabet_name}."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "classical.caesar.candidates",
            "implementation": "educational",
            "inputs": {"ciphertext": self.ciphertext, "alphabet": self.alphabet_name},
            "result": {"candidates": [dataclass_to_dict(item) for item in self.candidates]},
            "trace": [],
            "warnings": [
                "Exhaustive enumeration is feasible because the Caesar key space is small."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = " \\\\ ".join(
            rf"{item.shift} & \mathtt{{{item.plaintext}}}" for item in self.candidates
        )
        return rf"\begin{{array}}{{cl}}k&\text{{Candidate}}\\{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class FrequencyView:
    """Render basic character-frequency counts."""

    result: FrequencyResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Symbol", "Count", "Percentage")
        for entry in self.result.entries:
            table.add_row(entry.symbol, str(entry.count), f"{entry.percentage:.2f}%")
        console.print(table)
        most = ", ".join(self.result.most_frequent) or "(none)"
        console.print(f"Most frequent alphabet symbol(s): [bold]{most}[/bold]")
        if explain:
            console.print(f"Counted alphabet symbols: {self.result.total_alphabet_symbols}")
            console.print(f"Unknown symbols: {self.result.unknown_symbol_count}")
            console.print("No language model or automatic key inference was applied.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "classical.caesar.frequency",
            "implementation": "educational",
            "inputs": {"text": self.result.text, "alphabet": self.result.alphabet_name},
            "result": {
                "total_alphabet_symbols": self.result.total_alphabet_symbols,
                "unknown_symbol_count": self.result.unknown_symbol_count,
                "most_frequent": list(self.result.most_frequent),
                "entries": [dataclass_to_dict(entry) for entry in self.result.entries],
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = " \\\\ ".join(
            f"{entry.symbol} & {entry.count} & {entry.percentage:.2f}"
            for entry in self.result.entries
        )
        return rf"\begin{{array}}{{crr}}\text{{Symbol}}&\text{{Count}}&\%\\{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class VigenereView:
    """Render Vigenère encryption, decryption, and repeated-key alignment."""

    result: VigenereResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output)
        if explain:
            console.print(f"Alphabet: {self.result.alphabet_name}")
            console.print(f"Key: {self.result.key}")
            table = Table("Pos", "Input", "m", "Key pos", "Key", "k", "Output", "c")
            for entry in self.result.alignment:
                table.add_row(
                    str(entry.position),
                    repr(entry.input_symbol),
                    "—" if entry.input_index is None else str(entry.input_index),
                    "—" if entry.key_position is None else str(entry.key_position),
                    "—" if entry.key_symbol is None else entry.key_symbol,
                    "—" if entry.key_index is None else str(entry.key_index),
                    repr(entry.output_symbol),
                    "—" if entry.output_index is None else str(entry.output_index),
                )
            console.print(table)
            console.print("The key advances only when a message symbol belongs to the alphabet.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"classical.vigenere.{self.result.operation}",
            "implementation": "educational",
            "inputs": {
                "text": self.result.text,
                "key": self.result.key,
                "alphabet": self.result.alphabet_name,
                "unknown_policy": self.result.unknown_policy.value,
            },
            "result": {"output": self.result.output},
            "trace": (
                [dataclass_to_dict(entry) for entry in self.result.alignment] if explain else []
            ),
            "warnings": ["The repeated-key Vigenère cipher is not secure for modern use."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"c_i \equiv m_i + k_i \pmod{{{self.result.alphabet_size}}}",
            rf"\text{{Output: }}\mathtt{{{self.result.output}}}",
        ]
        if explain:
            lines.append(rf"\text{{Repeated key: }}\mathtt{{{self.result.key}}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class VigenereAlignmentView:
    """Render repeated-key alignment independently from encryption output."""

    result: VigenereResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Message: {self.result.text}")
        console.print(f"Repeated key: {self.result.key}")
        table = Table("Pos", "Input", "m", "Key pos", "Key", "k", "Output", "c")
        for entry in self.result.alignment:
            table.add_row(
                str(entry.position),
                repr(entry.input_symbol),
                "—" if entry.input_index is None else str(entry.input_index),
                "—" if entry.key_position is None else str(entry.key_position),
                "—" if entry.key_symbol is None else entry.key_symbol,
                "—" if entry.key_index is None else str(entry.key_index),
                repr(entry.output_symbol),
                "—" if entry.output_index is None else str(entry.output_index),
            )
        console.print(table)
        if explain:
            console.print(f"Alphabet: {self.result.alphabet_name}")
            console.print("The key advances only when a message symbol belongs to the alphabet.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "classical.vigenere.align",
            "implementation": "educational",
            "inputs": {
                "text": self.result.text,
                "key": self.result.key,
                "alphabet": self.result.alphabet_name,
                "unknown_policy": self.result.unknown_policy.value,
            },
            "result": {
                "repeated_key_alignment": [
                    dataclass_to_dict(entry) for entry in self.result.alignment
                ],
                "resulting_ciphertext": self.result.output,
            },
            "trace": [],
            "warnings": ["The repeated-key Vigenère cipher is not secure for modern use."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows: list[str] = []
        for entry in self.result.alignment:
            key_symbol = entry.key_symbol if entry.key_symbol is not None else r"\cdot"
            rows.append(
                f"{entry.position} & {entry.input_symbol} & {key_symbol} & {entry.output_symbol}"
            )
        return "\\begin{array}{rrrr}i&m_i&k_i&c_i\\\\" + " \\\\ ".join(rows) + "\\end{array}"


@dataclass(frozen=True, slots=True)
class PolybiusGridView:
    """Render a Polybius grid."""

    grid: PolybiusGrid

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Row\\Col", *(str(column) for column in range(1, self.grid.columns + 1)))
        for row in range(self.grid.rows):
            start = row * self.grid.columns
            cells = self.grid.cells[start : start + self.grid.columns]
            table.add_row(str(row + 1), *(cell if cell is not None else "·" for cell in cells))
        console.print(table)
        if explain:
            console.print("Coordinates are one-based and the grid is filled row by row.")
            console.print("A middle dot marks an unused trailing cell.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "classical.polybius.build",
            "implementation": "educational",
            "inputs": {"alphabet": self.grid.alphabet_name},
            "result": {
                "rows": self.grid.rows,
                "columns": self.grid.columns,
                "cells": list(self.grid.cells),
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows: list[str] = []
        for row in range(self.grid.rows):
            start = row * self.grid.columns
            cells = self.grid.cells[start : start + self.grid.columns]
            rows.append(" & ".join(cell if cell is not None else r"\cdot" for cell in cells))
        return rf"\begin{{array}}{{{'c' * self.grid.columns}}}{' \\\\ '.join(rows)}\end{{array}}"


@dataclass(frozen=True, slots=True)
class PolybiusView:
    """Render Polybius encryption or decryption."""

    result: PolybiusResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output_text)
        if explain:
            console.print(f"Grid: {self.result.rows}x{self.result.columns}")
            console.print(f"Alphabet: {self.result.alphabet_name}")
            table = Table("Pos", "Input", "Row", "Column", "Output", "Coordinate")
            for step in self.result.steps:
                table.add_row(
                    str(step.position),
                    repr(step.input_value),
                    "—" if step.row is None else str(step.row),
                    "—" if step.column is None else str(step.column),
                    repr(step.output_value),
                    str(step.transformed),
                )
            console.print(table)
            console.print(
                "Canonical ciphertext uses space-separated ROWCOLUMN tokens; preserved "
                "symbols use u+HEX tokens."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"classical.polybius.{self.result.operation}",
            "implementation": "educational",
            "inputs": {
                "text": self.result.input_text,
                "alphabet": self.result.alphabet_name,
                "rows": self.result.rows,
                "columns": self.result.columns,
                "unknown_policy": self.result.unknown_policy.value,
            },
            "result": {"output": self.result.output_text},
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": ["The Polybius square is an educational classical cipher."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"\text{{Output: }}\mathtt{{{self.result.output_text}}}"]
        if explain:
            lines.append(rf"\text{{Grid: {self.result.rows}\times{self.result.columns}}}")
        return "\\\n".join(lines)
