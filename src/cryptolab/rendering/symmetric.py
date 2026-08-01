"""Presentation objects for XOR, Vernam, and One-Time Pad requirements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.rendering.common import dataclass_to_dict
from cryptolab.symmetric.otp import OTPRequirement
from cryptolab.symmetric.vernam import VernamResult
from cryptolab.symmetric.xor import BitXORResult, ByteXORResult, XORTruthRow


@dataclass(frozen=True, slots=True)
class XORTruthTableView:
    """Render the XOR truth table."""

    rows: tuple[XORTruthRow, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        del explain
        table = Table("x", "y", "x XOR y")
        for row in self.rows:
            table.add_row(str(row.left), str(row.right), str(row.result))
        console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.xor.truth-table",
            "implementation": "educational",
            "inputs": {},
            "result": {"rows": [dataclass_to_dict(row) for row in self.rows]},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = r" \\ ".join(f"{row.left}&{row.right}&{row.result}" for row in self.rows)
        return rf"\begin{{array}}{{cc|c}}x&y&x\oplus y\\{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class BitXORView:
    """Render bitwise XOR."""

    result: BitXORResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output)
        if explain:
            console.print(f"Left:   {self.result.left}")
            console.print(f"Right:  {self.result.right}")
            console.print(f"Result: {self.result.output}")
            table = Table("Position", "Left", "Right", "XOR")
            for step in self.result.steps:
                table.add_row(str(step.position), str(step.left), str(step.right), str(step.result))
            console.print(table)
            console.print("XOR is self-inverse: (m XOR k) XOR k = m.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.xor.bits",
            "implementation": "educational",
            "inputs": {"left": self.result.left, "right": self.result.right},
            "result": {"output": self.result.output},
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\mathtt{{{self.result.left}}}\oplus\mathtt{{{self.result.right}}}"
            rf"=\mathtt{{{self.result.output}}}"
        ]
        if explain:
            lines.append(r"(m\oplus k)\oplus k=m")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ByteXORView:
    """Render bytewise XOR."""

    result: ByteXORResult
    left_source: str
    right_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output_hex)
        if explain:
            console.print(f"Left ({self.left_source}) hex:  {self.result.left_hex}")
            console.print(f"Right ({self.right_source}) hex: {self.result.right_hex}")
            console.print(f"Output hex:          {self.result.output_hex}")
            console.print(f"Left bits:  {self.result.left_bits}")
            console.print(f"Right bits: {self.result.right_bits}")
            console.print(f"Output bits:{self.result.output_bits}")
            table = Table("Byte", "Left", "Right", "XOR")
            for step in self.result.steps:
                table.add_row(
                    str(step.position),
                    f"{step.left:02x}",
                    f"{step.right:02x}",
                    f"{step.result:02x}",
                )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.xor.bytes",
            "implementation": "educational",
            "inputs": {
                "left_hex": self.result.left_hex,
                "left_source": self.left_source,
                "right_hex": self.result.right_hex,
                "right_source": self.right_source,
            },
            "result": {
                "output_hex": self.result.output_hex,
                "output_bits": self.result.output_bits,
                "length_bytes": self.result.length_bytes,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\mathtt{{{self.result.left_hex}}}\oplus\mathtt{{{self.result.right_hex}}}"
            rf"=\mathtt{{{self.result.output_hex}}}"
        ]
        if explain:
            lines.append(r"\text{Bytewise XOR over equal-length operands}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class VernamView:
    """Render Vernam encryption or decryption."""

    result: VernamResult
    input_source: str
    key_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output_hex)
        if explain:
            label = "Plaintext" if self.result.operation == "encrypt" else "Ciphertext"
            output_label = "Ciphertext" if self.result.operation == "encrypt" else "Plaintext"
            console.print(f"{label} ({self.input_source}) hex: {self.result.input_hex}")
            console.print(f"Key ({self.key_source}) hex: {self.result.key_hex}")
            console.print(f"{output_label} hex: {self.result.output_hex}")
            table = Table("Byte", label, "Key", output_label)
            for step in self.result.steps:
                table.add_row(
                    str(step.position),
                    f"{step.left:02x}",
                    f"{step.right:02x}",
                    f"{step.result:02x}",
                )
            console.print(table)
            console.print("The same XOR operation performs encryption and decryption.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"symmetric.vernam.{self.result.operation}",
            "implementation": "educational",
            "inputs": {
                "input_hex": self.result.input_hex,
                "input_source": self.input_source,
                "key_hex": self.result.key_hex,
                "key_source": self.key_source,
            },
            "result": {
                "output_hex": self.result.output_hex,
                "output_bits": self.result.output_bits,
                "length_bytes": self.result.length_bytes,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [
                "Vernam XOR is a true One-Time Pad only when every strict OTP requirement holds."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\mathtt{{{self.result.input_hex}}}\oplus\mathtt{{{self.result.key_hex}}}"
            rf"=\mathtt{{{self.result.output_hex}}}"
        ]
        if explain:
            lines.append(r"c_i=m_i\oplus k_i,\qquad m_i=c_i\oplus k_i")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class OTPRequirementsView:
    """Render strict One-Time Pad requirements."""

    requirements: tuple[OTPRequirement, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Requirement", "Necessary condition")
        for item in self.requirements:
            table.add_row(item.identifier, item.requirement)
        console.print(table)
        console.print(
            "CryptoLab cannot prove that a supplied key is uniformly random, secret, or unused."
        )
        if explain:
            rationale = Table("Requirement", "Rationale")
            for item in self.requirements:
                rationale.add_row(item.identifier, item.rationale)
            console.print(rationale)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.otp.requirements",
            "implementation": "educational",
            "inputs": {},
            "result": {
                "requirements": [dataclass_to_dict(item) for item in self.requirements],
                "cryptolab_can_verify_otp_status": False,
            },
            "trace": [],
            "warnings": ["The One-Time Pad is not presented as a general practical solution."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = r" \\ ".join(
            rf"\text{{{item.identifier}}}&\text{{{item.requirement}}}" for item in self.requirements
        )
        return rf"\begin{{array}}{{ll}}{rows}\end{{array}}"
