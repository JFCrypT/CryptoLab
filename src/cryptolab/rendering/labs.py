"""Presentation objects for controlled cryptanalysis laboratories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.labs.caesar_brute_force import CaesarBruteForceLabResult
from cryptolab.labs.models import LabDescriptor
from cryptolab.labs.vernam_key_reuse import VernamKeyReuseLabResult
from cryptolab.rendering.common import dataclass_to_dict


@dataclass(frozen=True, slots=True)
class LabListView:
    """Render the complete approved laboratory registry."""

    labs: tuple[LabDescriptor, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Identifier", "Title", "Status")
        for lab in self.labs:
            table.add_row(lab.identifier, lab.title, lab.status)
        console.print(table)
        if explain:
            console.print("Version 1.0.0 contains exactly these four approved laboratories.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "lab.list",
            "implementation": "controlled-laboratory",
            "inputs": {},
            "result": {"laboratories": [dataclass_to_dict(lab) for lab in self.labs]},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = r" \\ ".join(
            rf"\text{{{lab.identifier}}}&\text{{{lab.status}}}" for lab in self.labs
        )
        return rf"\begin{{array}}{{ll}}{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class CaesarBruteForceLabView:
    """Render the Caesar brute-force laboratory."""

    result: CaesarBruteForceLabResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Shift", "Candidate plaintext")
        for candidate in self.result.candidates:
            table.add_row(str(candidate.shift), candidate.plaintext)
        console.print(table)
        console.print(f"Key-space size: {self.result.key_space_size}")
        if self.result.ciphertext_frequency_symbols:
            console.print(
                "Most frequent ciphertext symbol(s): "
                + ", ".join(self.result.ciphertext_frequency_symbols)
            )
        if explain:
            console.print(f"Violated assumption: {self.result.violated_assumption}")
            console.print(f"Security effect: {self.result.security_effect}")
            console.print(f"Mitigation: {self.result.mitigation}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "lab.caesar-brute-force",
            "implementation": "controlled-laboratory",
            "inputs": {
                "ciphertext": self.result.ciphertext,
                "alphabet": self.result.alphabet_name,
            },
            "result": {
                "key_space_size": self.result.key_space_size,
                "candidates": [dataclass_to_dict(item) for item in self.result.candidates],
                "ciphertext_frequency_symbols": self.result.ciphertext_frequency_symbols,
                "violated_assumption": self.result.violated_assumption,
                "security_effect": self.result.security_effect,
                "mitigation": self.result.mitigation,
            },
            "trace": [],
            "warnings": ["This laboratory operates only on deliberately supplied local data."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"{item.shift}&\mathtt{{{item.plaintext}}}" for item in self.result.candidates
        )
        lines = [rf"\begin{{array}}{{rl}}k&\text{{candidate}}\\{rows}\end{{array}}"]
        if explain:
            lines.append(rf"\text{{Key-space size: }}{self.result.key_space_size}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class VernamKeyReuseLabView:
    """Render the Vernam key-reuse identity and its consequences."""

    result: VernamKeyReuseLabResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Value", "Hexadecimal")
        table.add_row("M1", self.result.message_one_hex)
        table.add_row("M2", self.result.message_two_hex)
        table.add_row("Reused key", self.result.reused_key_hex)
        table.add_row("C1", self.result.ciphertext_one_hex)
        table.add_row("C2", self.result.ciphertext_two_hex)
        table.add_row("C1 XOR C2", self.result.ciphertext_xor_hex)
        table.add_row("M1 XOR M2", self.result.plaintext_xor_hex)
        console.print(table)
        console.print(f"Identity holds: {self.result.identity_holds}")
        if explain:
            console.print(f"Violated assumption: {self.result.violated_assumption}")
            console.print(f"Security effect: {self.result.security_effect}")
            console.print(f"Mitigation: {self.result.mitigation}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "lab.vernam-key-reuse",
            "implementation": "controlled-laboratory",
            "inputs": {
                "message_one_hex": self.result.message_one_hex,
                "message_two_hex": self.result.message_two_hex,
                "reused_key_hex": self.result.reused_key_hex,
            },
            "result": {
                "ciphertext_one_hex": self.result.ciphertext_one_hex,
                "ciphertext_two_hex": self.result.ciphertext_two_hex,
                "ciphertext_xor_hex": self.result.ciphertext_xor_hex,
                "plaintext_xor_hex": self.result.plaintext_xor_hex,
                "identity_holds": self.result.identity_holds,
                "violated_assumption": self.result.violated_assumption,
                "security_effect": self.result.security_effect,
                "mitigation": self.result.mitigation,
            },
            "trace": [],
            "warnings": ["This laboratory uses deliberately vulnerable local examples."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            r"C_1\oplus C_2=(M_1\oplus K)\oplus(M_2\oplus K)=M_1\oplus M_2",
            rf"\mathtt{{{self.result.ciphertext_xor_hex}}}"
            rf"=\mathtt{{{self.result.plaintext_xor_hex}}}",
        ]
        if explain:
            lines.append(r"\text{Keystream reuse violates the one-time-use requirement.}")
        return "\\\n".join(lines)
