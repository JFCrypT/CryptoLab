"""Presentation objects for library-backed modern symmetric cryptography."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.rendering.common import dataclass_to_dict
from cryptolab.symmetric.modern import AEADProfile, AESModeProfile, ModernCipherResult


def _warnings_for_result(result: ModernCipherResult) -> list[str]:
    if result.algorithm == "ChaCha20-Poly1305" or result.mode == "gcm":
        return [
            "Nonce reuse with the same key can catastrophically break authenticated encryption."
        ]
    if result.mode == "ecb":
        return [
            "AES-ECB is included only for educational comparison and leaks repeated-block patterns."
        ]
    if result.mode == "xts":
        return [
            "AES-XTS is for storage data units and does not authenticate ciphertext modifications."
        ]
    return [f"AES-{result.mode.upper()} provides confidentiality but no authentication."]


@dataclass(frozen=True, slots=True)
class ModernCipherView:
    """Render one AES or ChaCha20-Poly1305 operation."""

    result: ModernCipherResult
    input_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output_hex)
        if self.result.tag_hex is not None and self.result.operation == "encrypt":
            console.print(f"Tag: {self.result.tag_hex}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Algorithm", self.result.algorithm)
            table.add_row("Operation", self.result.operation)
            table.add_row("Mode", self.result.mode)
            table.add_row("Key size", f"{self.result.key_size_bits} bits")
            aes_block_size = "128 bits" if self.result.algorithm.startswith("AES") else "—"
            table.add_row("AES block size", aes_block_size)
            table.add_row("Input source", self.input_source)
            table.add_row("Input length", f"{len(bytes.fromhex(self.result.input_hex))} bytes")
            table.add_row("Output length", f"{len(bytes.fromhex(self.result.output_hex))} bytes")
            table.add_row("Padding", self.result.padding)
            table.add_row("Authenticated", str(self.result.authenticated))
            table.add_row("Library", self.result.library)
            if self.result.parameter_name is not None:
                table.add_row(self.result.parameter_name, self.result.parameter_hex or "")
            if self.result.aad_hex is not None:
                table.add_row("AAD", self.result.aad_hex or "(empty)")
            console.print(table)
            for warning in _warnings_for_result(self.result):
                console.print(f"Warning: {warning}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        command_algorithm = (
            "chacha20-poly1305" if self.result.algorithm == "ChaCha20-Poly1305" else "aes"
        )
        result = {
            "output_hex": self.result.output_hex,
            "authenticated": self.result.authenticated,
            "padding": self.result.padding,
        }
        if self.result.tag_hex is not None:
            result["tag_hex"] = self.result.tag_hex
        return {
            "schema_version": "1.0",
            "command": f"symmetric.{command_algorithm}.{self.result.operation}",
            "implementation": "library-backed",
            "inputs": {
                "algorithm": self.result.algorithm,
                "mode": self.result.mode,
                "key_size_bits": self.result.key_size_bits,
                "input_hex": self.result.input_hex,
                "input_source": self.input_source,
                "parameter_name": self.result.parameter_name,
                "parameter_hex": self.result.parameter_hex,
                "aad_hex": self.result.aad_hex,
            },
            "result": result,
            "trace": [],
            "warnings": _warnings_for_result(self.result),
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\text{{{self.result.algorithm} {self.result.mode} {self.result.operation}}}",
            rf"\mathtt{{{self.result.input_hex}}}\longmapsto\mathtt{{{self.result.output_hex}}}",
        ]
        if self.result.tag_hex is not None:
            lines.append(rf"\operatorname{{tag}}=\mathtt{{{self.result.tag_hex}}}")
        if explain:
            lines.append(rf"\text{{Implementation: {self.result.library}}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class AESModeComparisonView:
    """Render the contextual comparison of every included AES mode."""

    profiles: tuple[AESModeProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Mode", "Purpose", "Padding", "Parameter", "Authentication")
        for item in self.profiles:
            table.add_row(
                item.mode,
                item.intended_purpose,
                item.padding,
                item.external_parameter,
                item.authentication,
            )
        console.print(table)
        if explain:
            detail = Table("Mode", "Parallelization", "Random access", "Main limitation")
            for item in self.profiles:
                detail.add_row(
                    item.mode,
                    item.parallelization,
                    item.random_access,
                    item.principal_limitation,
                )
            console.print(detail)
            console.print(
                "No mode is universally superior; selection depends on purpose and misuse risks."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.aes.compare-modes",
            "implementation": "explanatory",
            "inputs": {},
            "result": {"modes": [dataclass_to_dict(item) for item in self.profiles]},
            "trace": [],
            "warnings": ["Comparison is contextual and does not declare a universal winner."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"\text{{{item.mode}}}&\text{{{item.padding}}}&\text{{{item.authentication}}}"
            for item in self.profiles
        )
        lines = [
            rf"\begin{{array}}{{lll}}\text{{Mode}}&\text{{Padding}}"
            rf"&\text{{Authentication}}\\{rows}\end{{array}}"
        ]
        if explain:
            lines.append(r"\text{Mode selection is contextual.}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class AEADComparisonView:
    """Render the AES-GCM and ChaCha20-Poly1305 comparison."""

    profiles: tuple[AEADProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Construction", "Key", "Nonce", "Tag")
        for item in self.profiles:
            table.add_row(
                item.algorithm,
                item.key_size,
                item.nonce_size,
                item.authentication_tag,
            )
        console.print(table)
        if explain:
            detail = Table("Construction", "Behavior", "Principal misuse risk")
            for item in self.profiles:
                detail.add_row(
                    item.algorithm,
                    item.block_or_stream_behavior,
                    item.principal_misuse_risk,
                )
            console.print(detail)
            for item in self.profiles:
                console.print(f"{item.algorithm}: {item.common_strength}; {item.implementation}.")
            console.print(
                "Neither construction is universally superior without platform and protocol "
                "context."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "symmetric.compare-aead",
            "implementation": "explanatory",
            "inputs": {},
            "result": {"constructions": [dataclass_to_dict(item) for item in self.profiles]},
            "trace": [],
            "warnings": ["Nonce reuse is a critical misuse risk for both constructions."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"\text{{{item.algorithm}}}&\text{{{item.key_size}}}&\text{{{item.nonce_size}}}"
            for item in self.profiles
        )
        lines = [
            rf"\begin{{array}}{{lll}}\text{{AEAD}}&\text{{Key}}"
            rf"&\text{{Nonce}}\\{rows}\end{{array}}"
        ]
        if explain:
            lines.append(r"\text{Both constructions require nonce uniqueness per key.}")
        return "\\\n".join(lines)
