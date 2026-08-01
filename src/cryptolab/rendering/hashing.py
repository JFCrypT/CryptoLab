"""Presentation objects for hashing, HMAC, and HKDF."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.hashing.hashes import (
    AvalancheResult,
    DigestVerificationResult,
    HashMACProfile,
    HashProfile,
    HashResult,
)
from cryptolab.hashing.hkdf_sha256 import HKDFResult
from cryptolab.hashing.hmac_sha256 import HMACResult, HMACVerificationResult
from cryptolab.rendering.common import dataclass_to_dict


@dataclass(frozen=True, slots=True)
class HashDigestView:
    """Render one SHA-256 or SHA3-256 digest."""

    result: HashResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.digest_hex)
        if explain:
            table = Table("Property", "Value")
            table.add_row("Algorithm", self.result.algorithm.value)
            table.add_row("Digest size", f"{self.result.digest_size_bits} bits")
            table.add_row("Input source", self.result.source_kind)
            table.add_row("Input length", f"{self.result.input_length} bytes")
            table.add_row("Library", self.result.library)
            table.add_row("Keyed", "False")
            console.print(table)
            console.print("Warning: An unkeyed digest does not authenticate a sender.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.digest",
            "implementation": "library-backed",
            "inputs": {
                "algorithm": self.result.algorithm.value,
                "source_kind": self.result.source_kind,
                "input_length": self.result.input_length,
            },
            "result": {
                "digest_hex": self.result.digest_hex,
                "digest_size_bits": self.result.digest_size_bits,
            },
            "trace": [],
            "warnings": ["An unkeyed digest does not authenticate a sender."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\operatorname{{{self.result.algorithm.value}}}(M)="
            rf"\mathtt{{{self.result.digest_hex}}}"
        ]
        if explain:
            lines.append(rf"\lvert M\rvert={self.result.input_length}\text{{ bytes}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class DigestVerificationView:
    """Render successful digest verification."""

    result: DigestVerificationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Digest valid: {self.result.valid}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Algorithm", self.result.algorithm.value)
            table.add_row("Expected", self.result.expected_digest_hex)
            table.add_row("Computed", self.result.computed_digest_hex)
            table.add_row("Input source", self.result.source_kind)
            table.add_row("Input length", f"{self.result.input_length} bytes")
            table.add_row("Comparison", "hmac.compare_digest")
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.verify",
            "implementation": "library-backed",
            "inputs": {
                "algorithm": self.result.algorithm.value,
                "expected_digest_hex": self.result.expected_digest_hex,
                "source_kind": self.result.source_kind,
                "input_length": self.result.input_length,
            },
            "result": {
                "computed_digest_hex": self.result.computed_digest_hex,
                "valid": self.result.valid,
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{digest\ verified}}=\text{{{str(self.result.valid).lower()}}}"


@dataclass(frozen=True, slots=True)
class AvalancheView:
    """Render digest avalanche measurements and byte-level differences."""

    result: AvalancheResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        summary = Table("Property", "Value")
        summary.add_row("Algorithm", self.result.algorithm.value)
        summary.add_row("Input length", f"{self.result.input_length} bytes each")
        summary.add_row("Changed input bits", str(self.result.changed_input_bits))
        summary.add_row("Changed digest bits", f"{self.result.changed_digest_bits}/256")
        summary.add_row("Digest change", f"{self.result.changed_digest_percentage:.2f}%")
        console.print(summary)
        console.print(f"Left digest:  {self.result.left_digest_hex}")
        console.print(f"Right digest: {self.result.right_digest_hex}")
        console.print(f"Digest XOR:   {self.result.digest_xor_hex}")
        if explain:
            table = Table("Byte", "Left", "Right", "XOR", "Changed bits")
            for item in self.result.byte_differences:
                table.add_row(
                    str(item.index),
                    item.left_hex,
                    item.right_hex,
                    item.xor_hex,
                    str(item.changed_bits),
                )
            console.print(table)
            console.print(
                "This single observation illustrates diffusion; it is not a statistical proof of "
                "security."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        trace = (
            [dataclass_to_dict(item) for item in self.result.byte_differences] if explain else []
        )
        return {
            "schema_version": "1.0",
            "command": "hashing.avalanche",
            "implementation": "library-backed-analysis",
            "inputs": {
                "algorithm": self.result.algorithm.value,
                "input_length": self.result.input_length,
                "changed_input_bits": self.result.changed_input_bits,
            },
            "result": {
                "left_digest_hex": self.result.left_digest_hex,
                "right_digest_hex": self.result.right_digest_hex,
                "digest_xor_hex": self.result.digest_xor_hex,
                "changed_digest_bits": self.result.changed_digest_bits,
                "digest_bits": self.result.digest_bits,
                "changed_digest_percentage": self.result.changed_digest_percentage,
            },
            "trace": trace,
            "warnings": [
                "One avalanche observation is illustrative and is not a statistical proof "
                "of security."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\Delta_{{\mathrm{{in}}}}={self.result.changed_input_bits}\text{{ bits}}",
            rf"\Delta_{{\mathrm{{digest}}}}={self.result.changed_digest_bits}/256",
            rf"\mathrm{{change}}={self.result.changed_digest_percentage:.2f}\%",
        ]
        if explain:
            lines.append(r"\text{This is an illustrative observation, not a security proof.}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class HashComparisonView:
    """Render the SHA-256 and SHA3-256 comparison."""

    profiles: tuple[HashProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Algorithm", "Family", "Digest", "Internal structure", "API")
        for item in self.profiles:
            table.add_row(
                item.algorithm,
                item.family,
                item.digest_size,
                item.internal_structure,
                item.practical_api,
            )
        console.print(table)
        if explain:
            for item in self.profiles:
                console.print(f"{item.algorithm}: {item.principal_note}.")
            console.print("Neither digest is a MAC merely because its output is 256 bits.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.compare-hashes",
            "implementation": "comparison",
            "inputs": {},
            "result": {"algorithms": [dataclass_to_dict(item) for item in self.profiles]},
            "trace": [],
            "warnings": ["Equal digest size does not imply equal internal construction."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"\text{{{item.algorithm}}}&\text{{{item.family}}}&\text{{{item.digest_size}}}"
            for item in self.profiles
        )
        lines = [
            rf"\begin{{array}}{{lll}}\text{{Algorithm}}&\text{{Family}}&\text{{Digest}}\\{rows}"
            r"\end{array}"
        ]
        if explain:
            lines.append(r"\text{SHA-2 and SHA-3 use different internal construction families.}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class HashMACComparisonView:
    """Render the required distinction between hashing and HMAC."""

    profiles: tuple[HashMACProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Construction", "Secret key", "Primary property", "Verification")
        for item in self.profiles:
            table.add_row(
                item.construction,
                item.key_requirement,
                item.primary_property,
                item.typical_verification,
            )
        console.print(table)
        if explain:
            for item in self.profiles:
                console.print(f"{item.construction}: {item.limitation}.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.compare-hash-mac",
            "implementation": "comparison",
            "inputs": {},
            "result": {
                "constructions": [
                    {
                        "construction": item.construction,
                        "secret_key": item.key_requirement,
                        "primary_property": item.primary_property,
                        "typical_verification": item.typical_verification,
                        "limitation": item.limitation,
                    }
                    for item in self.profiles
                ]
            },
            "trace": [],
            "warnings": ["A plain hash does not provide sender authentication."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"\text{{{item.construction}}}&\text{{{item.key_requirement}}}"
            for item in self.profiles
        )
        lines = [
            rf"\begin{{array}}{{ll}}\text{{Construction}}&\text{{Secret key}}\\{rows}"
            r"\end{array}"
        ]
        if explain:
            lines.append(r"\text{A digest is not a message authentication code.}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class HMACView:
    """Render HMAC-SHA-256 generation."""

    result: HMACResult
    key_source: str
    message_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.tag_hex)
        if explain:
            table = Table("Property", "Value")
            table.add_row("Construction", "HMAC-SHA-256")
            table.add_row("Tag size", "256 bits")
            table.add_row("Key source", self.key_source)
            table.add_row("Key length", f"{self.result.key_length} bytes")
            table.add_row("Message source", self.message_source)
            table.add_row("Message length", f"{self.result.message_length} bytes")
            table.add_row("Library", self.result.library)
            console.print(table)
            console.print("HMAC is a symmetric MAC, not a digital signature.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.hmac-sha256.generate",
            "implementation": "library-backed",
            "inputs": {
                "key_source": self.key_source,
                "key_length": self.result.key_length,
                "message_source": self.message_source,
                "message_length": self.result.message_length,
            },
            "result": {"tag_hex": self.result.tag_hex, "tag_size_bits": 256},
            "trace": [],
            "warnings": ["HMAC is a symmetric MAC and is not a digital signature."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"\operatorname{{HMAC-SHA-256}}(K,M)=\mathtt{{{self.result.tag_hex}}}"]
        if explain:
            lines.append(r"\text{The verifier must possess the shared secret key.}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class HMACVerificationView:
    """Render successful HMAC-SHA-256 verification."""

    result: HMACVerificationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Tag valid: {self.result.valid}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Expected tag", self.result.expected_tag_hex)
            table.add_row("Computed tag", self.result.computed_tag_hex)
            table.add_row("Key length", f"{self.result.key_length} bytes")
            table.add_row("Message length", f"{self.result.message_length} bytes")
            table.add_row("Comparison", "hmac.compare_digest")
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "hashing.hmac-sha256.verify",
            "implementation": "library-backed",
            "inputs": {
                "expected_tag_hex": self.result.expected_tag_hex,
                "key_length": self.result.key_length,
                "message_length": self.result.message_length,
            },
            "result": {
                "computed_tag_hex": self.result.computed_tag_hex,
                "valid": self.result.valid,
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{HMAC\ verified}}=\text{{{str(self.result.valid).lower()}}}"


@dataclass(frozen=True, slots=True)
class HKDFView:
    """Render HKDF-SHA-256 extract and expand stages."""

    result: HKDFResult
    ikm_source: str
    salt_source: str
    info_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"PRK: {self.result.prk_hex}")
        console.print(f"OKM: {self.result.okm_hex}")
        if explain:
            table = Table("Stage or property", "Value")
            table.add_row("Hash", self.result.hash_algorithm)
            table.add_row("IKM source", self.ikm_source)
            table.add_row("IKM length", f"{self.result.ikm_length} bytes")
            table.add_row("Salt source", self.salt_source)
            table.add_row("Effective salt", self.result.effective_salt_hex)
            table.add_row("Extract output (PRK)", self.result.prk_hex)
            table.add_row("Info source", self.info_source)
            table.add_row("Info", self.result.info_hex or "(empty)")
            table.add_row("Expand length", f"{self.result.output_length} bytes")
            table.add_row("Expand output (OKM)", self.result.okm_hex)
            table.add_row("Library", self.result.library)
            table.add_row(
                "Complete derivation cross-check",
                str(self.result.complete_derivation_matches),
            )
            console.print(table)
            console.print(
                "HKDF derives keys from key material; it is not a password-hashing function."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        trace = []
        if explain:
            trace = [
                {"stage": "extract", "output_name": "prk", "output_hex": self.result.prk_hex},
                {
                    "stage": "expand",
                    "output_name": "okm",
                    "output_hex": self.result.okm_hex,
                    "length": self.result.output_length,
                },
            ]
        return {
            "schema_version": "1.0",
            "command": "hashing.hkdf-sha256.derive",
            "implementation": "library-backed",
            "inputs": {
                "ikm_source": self.ikm_source,
                "ikm_length": self.result.ikm_length,
                "salt_source": self.salt_source,
                "salt_provided": self.result.salt_provided,
                "effective_salt_hex": self.result.effective_salt_hex,
                "info_source": self.info_source,
                "info_hex": self.result.info_hex,
                "output_length": self.result.output_length,
            },
            "result": {
                "prk_hex": self.result.prk_hex,
                "okm_hex": self.result.okm_hex,
                "complete_derivation_matches": self.result.complete_derivation_matches,
            },
            "trace": trace,
            "warnings": ["HKDF is not a password-hashing function."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\operatorname{{PRK}}=\mathtt{{{self.result.prk_hex}}}",
            rf"\operatorname{{OKM}}=\mathtt{{{self.result.okm_hex}}}",
        ]
        if explain:
            lines.append(
                rf"\lvert\operatorname{{OKM}}\rvert={self.result.output_length}"
                r"\text{ bytes}"
            )
        return "\\\n".join(lines)
