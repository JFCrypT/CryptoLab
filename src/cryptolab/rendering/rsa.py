"""Presentation objects for educational and library-backed RSA."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.public_key.rsa_applied import (
    RSAKeyPairMaterial,
    RSAOAEPResult,
    RSAProfile,
    RSAPSSResult,
    RSAPSSVerificationResult,
)
from cryptolab.public_key.rsa_educational import (
    EducationalRSADecryptionResult,
    EducationalRSAGenerationResult,
    EducationalRSAKey,
    EducationalRSAOperationResult,
    IntegerBytesResult,
)
from cryptolab.rendering.common import dataclass_to_dict

TEXTBOOK_WARNING = "Textbook RSA is deterministic educational code and is insecure for real data."
APPLIED_WARNING = (
    "Library-backed operations demonstrate correct APIs but do not provide a complete "
    "key-management or hybrid-encryption protocol."
)


def _key_table(key: EducationalRSAKey) -> Table:
    table = Table("Parameter", "Value", "Meaning")
    table.add_row("p", str(key.p), "First secret prime")
    table.add_row("q", str(key.q), "Second secret prime")
    table.add_row("n", str(key.n), "RSA modulus p*q")
    table.add_row("phi(n)", str(key.phi), "Euler totient")
    table.add_row("lambda(n)", str(key.carmichael), "Carmichael function")
    table.add_row("e", str(key.e), "Public exponent")
    table.add_row("d", str(key.d), "Private exponent modulo phi(n)")
    table.add_row("d_lambda", str(key.d_carmichael), "Minimal inverse modulo lambda(n)")
    table.add_row("dP", str(key.dp), "d mod (p-1)")
    table.add_row("dQ", str(key.dq), "d mod (q-1)")
    table.add_row("qInv", str(key.q_inverse_mod_p), "q^(-1) mod p")
    table.add_row("pInv", str(key.p_inverse_mod_q), "p^(-1) mod q")
    return table


@dataclass(frozen=True, slots=True)
class EducationalRSAKeyView:
    """Render one manually constructed educational RSA key."""

    key: EducationalRSAKey

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(_key_table(self.key))
        if explain:
            console.print(f"Public key: (e, n) = ({self.key.e}, {self.key.n})")
            console.print(
                f"Private teaching key: (d, p, q) = ({self.key.d}, {self.key.p}, {self.key.q})"
            )
            console.print(f"Check: e*d mod phi(n) = {(self.key.e * self.key.d) % self.key.phi}")
            console.print(
                "The phi(n) and lambda(n) inverses are equivalent private exponents modulo "
                "lambda(n)."
            )
            console.print(f"Warning: {TEXTBOOK_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.educational.inspect",
            "implementation": "educational",
            "inputs": {"p": self.key.p, "q": self.key.q, "e": self.key.e},
            "result": dataclass_to_dict(self.key),
            "trace": [],
            "warnings": [TEXTBOOK_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"n={self.key.p}\cdot {self.key.q}={self.key.n}",
            rf"\varphi(n)=({self.key.p}-1)({self.key.q}-1)={self.key.phi}",
            rf"\lambda(n)=\operatorname{{lcm}}({self.key.p - 1},"
            rf"{self.key.q - 1})={self.key.carmichael}",
            rf"e={self.key.e},\quad d_{{\varphi}}={self.key.d},\quad "
            rf"d_{{\lambda}}={self.key.d_carmichael}",
        ]
        if explain:
            lines.append(rf"ed_{{\varphi}}\equiv 1\pmod{{{self.key.phi}}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class EducationalRSAGenerationView:
    """Render one generated educational RSA key."""

    result: EducationalRSAGenerationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(_key_table(self.result.key))
        if explain:
            console.print(f"Requested prime size: {self.result.prime_bits} bits")
            console.print(f"Generation attempts: {self.result.attempts}")
            console.print(f"Randomness source: {self.result.randomness}")
            console.print(f"Warning: {TEXTBOOK_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.educational.generate",
            "implementation": "educational",
            "inputs": {"prime_bits": self.result.prime_bits, "e": self.result.key.e},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [TEXTBOOK_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        return EducationalRSAKeyView(self.result.key).render_latex(explain=explain)


@dataclass(frozen=True, slots=True)
class EducationalRSAOperationView:
    """Render textbook RSA encryption."""

    result: EducationalRSAOperationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        symbol = "c" if self.result.operation == "encrypt" else "m"
        console.print(
            f"{symbol} = {self.result.input_value}^{self.result.exponent} mod "
            f"{self.result.modulus} = {self.result.output_value}"
        )
        if explain:
            table = Table("Exponent", "Bit", "Accumulator", "Squared base")
            for step in self.result.steps:
                table.add_row(
                    str(step.exponent),
                    str(step.bit),
                    str(step.accumulator),
                    str(step.base),
                )
            console.print(table)
            console.print("Deterministic: True")
            console.print(f"Warning: {TEXTBOOK_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"public-key.rsa.educational.{self.result.operation}",
            "implementation": "educational",
            "inputs": {
                "value": self.result.input_value,
                "exponent": self.result.exponent,
                "modulus": self.result.modulus,
            },
            "result": {
                "output_value": self.result.output_value,
                "deterministic": self.result.deterministic,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [TEXTBOOK_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        line = (
            rf"{self.result.input_value}^{{{self.result.exponent}}}\bmod "
            rf"{self.result.modulus}={self.result.output_value}"
        )
        if explain:
            return line + "\\\n\\text{Textbook RSA is deterministic and educational.}"
        return line


@dataclass(frozen=True, slots=True)
class EducationalRSADecryptionView:
    """Render textbook RSA decryption and CRT reconstruction."""

    result: EducationalRSADecryptionResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Plaintext representative: {self.result.plaintext}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Ciphertext", str(self.result.ciphertext))
            table.add_row("Standard exponentiation", str(self.result.standard_plaintext))
            table.add_row("m1 = c^dP mod p", str(self.result.m1))
            table.add_row("m2 = c^dQ mod q", str(self.result.m2))
            table.add_row("h = qInv*(m1-m2) mod p", str(self.result.h))
            table.add_row("CRT reconstruction", str(self.result.crt_plaintext))
            table.add_row("CRT matches standard", str(self.result.crt_matches_standard))
            console.print(table)
            console.print(f"Warning: {TEXTBOOK_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.educational.decrypt",
            "implementation": "educational",
            "inputs": {"ciphertext": self.result.ciphertext},
            "result": {
                "plaintext": self.result.plaintext,
                "standard_plaintext": self.result.standard_plaintext,
                "crt_plaintext": self.result.crt_plaintext,
                "m1": self.result.m1,
                "m2": self.result.m2,
                "h": self.result.h,
                "crt_matches_standard": self.result.crt_matches_standard,
            },
            "trace": (
                [dataclass_to_dict(step) for step in self.result.standard_steps] if explain else []
            ),
            "warnings": [TEXTBOOK_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"m={self.result.plaintext}"]
        if explain:
            lines.append(
                rf"m_1={self.result.m1},\quad m_2={self.result.m2},\quad h={self.result.h}"
            )
            lines.append(rf"m=m_2+hq={self.result.crt_plaintext}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class IntegerBytesView:
    """Render unsigned big-endian conversion."""

    result: IntegerBytesResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        if self.result.operation == "integer-to-bytes":
            console.print(self.result.bytes_hex)
        else:
            console.print(str(self.result.integer))
        if explain:
            table = Table("Property", "Value")
            table.add_row("Integer", str(self.result.integer))
            table.add_row("Bytes", self.result.bytes_hex)
            table.add_row("Length", f"{self.result.length} bytes")
            table.add_row("Byte order", self.result.byte_order)
            table.add_row("Signed", str(self.result.signed))
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"public-key.rsa.convert.{self.result.operation}",
            "implementation": "educational",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"{self.result.integer}\longleftrightarrow\mathtt{{{self.result.bytes_hex}}}"


@dataclass(frozen=True, slots=True)
class RSAKeyGenerationView:
    """Render applied RSA key-generation metadata without private key bytes."""

    result: RSAKeyPairMaterial
    private_path: str
    public_path: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Property", "Value")
        table.add_row("Key size", f"{self.result.key_size_bits} bits")
        table.add_row("Public exponent", str(self.result.public_exponent))
        table.add_row("Private-key path", self.private_path)
        table.add_row("Public-key path", self.public_path)
        table.add_row("Public fingerprint (SHA-256)", self.result.public_fingerprint_sha256)
        console.print(table)
        if explain:
            console.print(f"Private format: {self.result.private_format}")
            console.print(f"Public format: {self.result.public_format}")
            console.print(
                "Private-key encryption: none; file permissions are restricted to the owner."
            )
            console.print(f"Warning: {APPLIED_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.applied.generate",
            "implementation": "library-backed",
            "inputs": {"key_size_bits": self.result.key_size_bits},
            "result": {
                "public_exponent": self.result.public_exponent,
                "private_key_path": self.private_path,
                "public_key_path": self.public_path,
                "public_fingerprint_sha256": self.result.public_fingerprint_sha256,
                "private_format": self.result.private_format,
                "public_format": self.result.public_format,
                "private_encrypted": self.result.private_encrypted,
            },
            "trace": [],
            "warnings": [APPLIED_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        lines = [
            rf"\text{{RSA key size}}={self.result.key_size_bits}\text{{ bits}}",
            rf"e={self.result.public_exponent}",
            rf"\operatorname{{SHA256}}(K_{{pub}})="
            rf"\mathtt{{{self.result.public_fingerprint_sha256}}}",
        ]
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class RSAOAEPView:
    """Render RSA-OAEP encryption or decryption."""

    result: RSAOAEPResult
    input_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output_hex)
        if explain:
            table = Table("Property", "Value")
            table.add_row("Scheme", "RSA-OAEP")
            table.add_row("Operation", self.result.operation)
            table.add_row("Key size", f"{self.result.key_size_bits} bits")
            table.add_row("Input source", self.input_source)
            table.add_row("Input length", f"{len(bytes.fromhex(self.result.input_hex))} bytes")
            table.add_row("Output length", f"{len(bytes.fromhex(self.result.output_hex))} bytes")
            table.add_row("Maximum plaintext", f"{self.result.maximum_message_bytes} bytes")
            table.add_row("Hash", self.result.hash_algorithm)
            table.add_row("Mask generation", self.result.mgf)
            table.add_row("Label", "empty")
            table.add_row("Randomized encryption", str(self.result.randomized))
            table.add_row("Library", self.result.library)
            console.print(table)
            console.print(
                "RSA-OAEP is for short messages such as symmetric keys; "
                "bulk data needs hybrid encryption."
            )
            console.print(f"Warning: {APPLIED_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"public-key.rsa.applied.oaep-{self.result.operation}",
            "implementation": "library-backed",
            "inputs": {
                "input_hex": self.result.input_hex,
                "input_source": self.input_source,
                "key_size_bits": self.result.key_size_bits,
                "hash_algorithm": self.result.hash_algorithm,
                "mgf": self.result.mgf,
                "label_hex": self.result.label_hex,
            },
            "result": {
                "output_hex": self.result.output_hex,
                "maximum_message_bytes": self.result.maximum_message_bytes,
                "randomized": self.result.randomized,
            },
            "trace": [],
            "warnings": [
                "RSA-OAEP is limited to short messages; use hybrid encryption for bulk data."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\operatorname{{RSA\text{{-}}OAEP}}(\mathtt{{{self.result.input_hex}}})="
            rf"\mathtt{{{self.result.output_hex}}}"
        ]
        if explain:
            lines.append(rf"m_{{max}}={self.result.maximum_message_bytes}\text{{ bytes}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class RSAPSSView:
    """Render one RSA-PSS signature."""

    result: RSAPSSResult
    message_source: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.signature_hex)
        if explain:
            table = Table("Property", "Value")
            table.add_row("Scheme", "RSA-PSS")
            table.add_row("Key size", f"{self.result.key_size_bits} bits")
            table.add_row("Message source", self.message_source)
            table.add_row("Message length", f"{len(bytes.fromhex(self.result.message_hex))} bytes")
            table.add_row(
                "Signature length",
                f"{len(bytes.fromhex(self.result.signature_hex))} bytes",
            )
            table.add_row("Hash", self.result.hash_algorithm)
            table.add_row("Mask generation", self.result.mgf)
            table.add_row("Salt length", f"{self.result.salt_length_bytes} bytes")
            table.add_row("Randomized", str(self.result.randomized))
            table.add_row("Library", self.result.library)
            console.print(table)
            console.print("RSA-PSS signs; it does not encrypt the message.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.applied.pss-sign",
            "implementation": "library-backed",
            "inputs": {
                "message_hex": self.result.message_hex,
                "message_source": self.message_source,
                "key_size_bits": self.result.key_size_bits,
                "hash_algorithm": self.result.hash_algorithm,
                "mgf": self.result.mgf,
                "salt_length_bytes": self.result.salt_length_bytes,
            },
            "result": {
                "signature_hex": self.result.signature_hex,
                "randomized": self.result.randomized,
            },
            "trace": [],
            "warnings": ["A digital signature provides authenticity, not confidentiality."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return (
            rf"\sigma=\operatorname{{RSA\text{{-}}PSS}}(M)="
            rf"\mathtt{{{self.result.signature_hex}}}"
        )


@dataclass(frozen=True, slots=True)
class RSAPSSVerificationView:
    """Render successful RSA-PSS verification."""

    result: RSAPSSVerificationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Signature valid: {self.result.valid}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Scheme", "RSA-PSS")
            table.add_row("Key size", f"{self.result.key_size_bits} bits")
            table.add_row("Hash", self.result.hash_algorithm)
            table.add_row("Salt length", f"{self.result.salt_length_bytes} bytes")
            table.add_row("Message length", f"{len(bytes.fromhex(self.result.message_hex))} bytes")
            table.add_row(
                "Signature length",
                f"{len(bytes.fromhex(self.result.signature_hex))} bytes",
            )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.applied.pss-verify",
            "implementation": "library-backed",
            "inputs": {
                "message_hex": self.result.message_hex,
                "signature_hex": self.result.signature_hex,
                "key_size_bits": self.result.key_size_bits,
            },
            "result": {"valid": self.result.valid},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{Verify}}_{{RSA\text{{-}}PSS}}={str(self.result.valid).lower()}"


@dataclass(frozen=True, slots=True)
class RSAComparisonView:
    """Render the contextual comparison of textbook RSA, OAEP, and PSS."""

    profiles: tuple[RSAProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Construction", "Category", "Purpose", "Padding/encoding", "Randomized")
        for item in self.profiles:
            table.add_row(
                item.construction,
                item.category,
                item.purpose,
                item.encoding_or_padding,
                item.randomized,
            )
        console.print(table)
        if explain:
            details = Table("Construction", "Key operation", "Principal limitation")
            for item in self.profiles:
                details.add_row(item.construction, item.key_operation, item.principal_limitation)
            console.print(details)
            console.print(
                "Encryption and signing are different operations with different key directions."
            )
            console.print(
                "Hybrid encryption uses RSA-OAEP for a short symmetric key and AEAD for bulk data."
            )
            console.print(
                "No RSA construction is universally preferable outside its intended purpose."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.rsa.compare",
            "implementation": "explanatory",
            "inputs": {},
            "result": {"constructions": [dataclass_to_dict(item) for item in self.profiles]},
            "trace": [],
            "warnings": ["Textbook RSA must not protect real data."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"\text{{{item.construction}}}&\text{{{item.category}}}&\text{{{item.purpose}}}"
            for item in self.profiles
        )
        lines = [
            rf"\begin{{array}}{{lll}}\text{{Construction}}&\text{{Category}}&"
            rf"\text{{Purpose}}\\{rows}\end{{array}}"
        ]
        if explain:
            lines.append(r"\text{Textbook RSA is educational; OAEP encrypts; PSS signs.}")
        return "\\\n".join(lines)
