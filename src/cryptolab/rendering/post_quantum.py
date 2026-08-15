"""Presentation objects for post-quantum foundations and standardized PQC primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.post_quantum.comparisons import PQCComparisonProfile
from cryptolab.post_quantum.foundations import (
    NegacyclicMultiplicationResult,
    ToyLWEResult,
)
from cryptolab.post_quantum.ml_dsa import (
    MLDSAProfile,
    MLDSASignatureResult,
    MLDSAVerificationResult,
)
from cryptolab.post_quantum.ml_kem import (
    MLKEMDecapsulationResult,
    MLKEMEncapsulationResult,
    MLKEMProfile,
)
from cryptolab.post_quantum.openssl_backend import OpenSSLKeyPairMaterial, OpenSSLPQCStatus
from cryptolab.post_quantum.slh_dsa import (
    SLHDSAProfile,
    SLHDSASignatureResult,
    SLHDSAVerificationResult,
)
from cryptolab.rendering.common import dataclass_to_dict

PQC_BACKEND_WARNING = (
    "Standardized PQC operations require OpenSSL 3.5+ and are delegated to its EVP provider."
)
PQC_KEM_WARNING = (
    "ML-KEM establishes key material; it does not encrypt arbitrary application messages directly."
)
PQC_IDENTITY_WARNING = (
    "A valid digital signature proves possession of the signing private key, "
    "not a real-world identity."
)
PQC_EDUCATIONAL_WARNING = (
    "Toy polynomial and LWE examples are educational only and are not ML-KEM or ML-DSA."
)


def _vector(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


@dataclass(frozen=True, slots=True)
class OpenSSLPQCStatusView:
    """Render OpenSSL PQC backend availability."""

    result: OpenSSLPQCStatus

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Property", "Value")
        table.add_row("Executable", self.result.executable)
        table.add_row("Version", self.result.version_text)
        table.add_row("Minimum", self.result.minimum_version)
        table.add_row("ML-KEM parameter sets", str(len(self.result.ml_kem)))
        table.add_row("ML-DSA parameter sets", str(len(self.result.ml_dsa)))
        table.add_row("SLH-DSA parameter sets", str(len(self.result.slh_dsa)))
        table.add_row("PQC backend ready", str(self.result.ready))
        console.print(table)
        if explain:
            console.print(f"ML-KEM: {', '.join(self.result.ml_kem) or 'none'}")
            console.print(f"ML-DSA: {', '.join(self.result.ml_dsa) or 'none'}")
            console.print(f"SLH-DSA: {', '.join(self.result.slh_dsa) or 'none'}")
            console.print(f"Warning: {PQC_BACKEND_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.backend",
            "implementation": "library-backed",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [PQC_BACKEND_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{OpenSSL\ PQC\ ready}}={str(self.result.ready).lower()}"


@dataclass(frozen=True, slots=True)
class NegacyclicMultiplicationView:
    """Render tiny negacyclic polynomial-ring multiplication."""

    result: NegacyclicMultiplicationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"Result in Z_{self.result.modulus}[x]/(x^{self.result.degree}+1): "
            f"{_vector(self.result.result)}"
        )
        if explain:
            table = Table("i", "j", "raw degree", "reduced degree", "sign", "contribution")
            for term in self.result.terms:
                table.add_row(
                    str(term.left_index),
                    str(term.right_index),
                    str(term.raw_degree),
                    str(term.reduced_degree),
                    "+" if term.sign > 0 else "-",
                    str(term.contribution),
                )
            console.print(table)
            console.print(f"Warning: {PQC_EDUCATIONAL_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.foundations.ring-multiply",
            "implementation": "educational",
            "inputs": {
                "modulus": self.result.modulus,
                "left": list(self.result.left),
                "right": list(self.result.right),
            },
            "result": {"coefficients": list(self.result.result)},
            "trace": [dataclass_to_dict(term) for term in self.result.terms] if explain else [],
            "warnings": [PQC_EDUCATIONAL_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        coefficients = ",".join(str(value) for value in self.result.result)
        lines = [
            rf"(a(x)b(x))\bmod(x^{{{self.result.degree}}}+1,{self.result.modulus})"
            rf"=({coefficients})"
        ]
        if explain:
            lines.append(r"\text{Educational negacyclic ring example only}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ToyLWEView:
    """Render a tiny b = A*s + e mod q example."""

    result: ToyLWEResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"b = A*s + e mod {self.result.modulus} = {_vector(self.result.output)}")
        if explain:
            table = Table("Row", "dot(A_i, s)", "e_i", "b_i")
            for index, row in enumerate(self.result.rows):
                table.add_row(
                    str(index),
                    str(row.dot_product),
                    str(row.error),
                    str(row.value),
                )
            console.print(table)
            console.print(f"Secret s: {_vector(self.result.secret)}")
            console.print(f"Error e: {_vector(self.result.error)}")
            console.print(f"Warning: {PQC_EDUCATIONAL_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.foundations.lwe-example",
            "implementation": "educational",
            "inputs": {
                "modulus": self.result.modulus,
                "matrix": [list(row) for row in self.result.matrix],
                "secret": list(self.result.secret),
                "error": list(self.result.error),
            },
            "result": {"b": list(self.result.output)},
            "trace": [dataclass_to_dict(row) for row in self.result.rows] if explain else [],
            "warnings": [PQC_EDUCATIONAL_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        output = ",".join(str(value) for value in self.result.output)
        lines = [rf"b=As+e\pmod{{{self.result.modulus}}}=({output})"]
        if explain:
            lines.append(r"\text{Toy LWE-style sample; not a standardized PQC primitive}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class MLKEMParametersView:
    """Render FIPS 203 parameter sets."""

    profiles: tuple[MLKEMProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Parameter set", "Category", "pk", "sk", "ciphertext", "secret")
        for profile in self.profiles:
            table.add_row(
                profile.parameter_set,
                str(profile.security_category),
                str(profile.public_key_bytes),
                str(profile.private_key_bytes),
                str(profile.ciphertext_bytes),
                str(profile.shared_secret_bytes),
            )
        console.print(table)
        if explain:
            console.print("Sizes are raw FIPS 203 values in bytes, not PEM serialization sizes.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.ml-kem.parameters",
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = [
            rf"\text{{{p.parameter_set}}}&{p.public_key_bytes}&{p.ciphertext_bytes}"
            for p in self.profiles
        ]
        return "\\\n".join(rows)


@dataclass(frozen=True, slots=True)
class MLDSAParametersView:
    """Render FIPS 204 parameter sets."""

    profiles: tuple[MLDSAProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Parameter set", "Category", "pk", "sk", "signature")
        for profile in self.profiles:
            table.add_row(
                profile.parameter_set,
                str(profile.security_category),
                str(profile.public_key_bytes),
                str(profile.private_key_bytes),
                str(profile.signature_bytes),
            )
        console.print(table)
        if explain:
            console.print("Sizes are raw FIPS 204 values in bytes, not PEM serialization sizes.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.ml-dsa.parameters",
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return "\\\n".join(
            rf"\text{{{p.parameter_set}}}&{p.public_key_bytes}&{p.signature_bytes}"
            for p in self.profiles
        )


@dataclass(frozen=True, slots=True)
class SLHDSAParametersView:
    """Render FIPS 205 parameter sets."""

    profiles: tuple[SLHDSAProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Parameter set", "Hash", "Goal", "Category", "pk", "sk", "signature")
        for profile in self.profiles:
            table.add_row(
                profile.parameter_set,
                profile.hash_family,
                profile.optimization,
                str(profile.security_category),
                str(profile.public_key_bytes),
                str(profile.private_key_bytes),
                str(profile.signature_bytes),
            )
        console.print(table)
        if explain:
            console.print("'small' prioritizes signature size; 'fast' prioritizes signing speed.")
            console.print("Sizes are raw FIPS 205 values in bytes, not PEM serialization sizes.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.slh-dsa.parameters",
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return "\\\n".join(
            rf"\text{{{p.parameter_set}}}&{p.public_key_bytes}&{p.signature_bytes}"
            for p in self.profiles
        )


@dataclass(frozen=True, slots=True)
class PQCKeyGenerationView:
    """Render generated PQC key material without exposing the private key."""

    result: OpenSSLKeyPairMaterial
    private_path: str
    public_path: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Property", "Value")
        table.add_row("Algorithm", self.result.algorithm)
        table.add_row("Standard", self.result.standard)
        table.add_row("Private-key path", self.private_path)
        table.add_row("Public-key path", self.public_path)
        table.add_row("Public fingerprint (SHA-256)", self.result.public_fingerprint_sha256)
        table.add_row("Private format", self.result.private_format)
        table.add_row("Public format", self.result.public_format)
        table.add_row("Backend", self.result.library)
        console.print(table)
        if explain:
            console.print("The private key is written with mode 0600; the public key uses 0644.")
            console.print(f"Warning: {PQC_BACKEND_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"post-quantum.{self.result.algorithm.lower()}.generate",
            "implementation": "library-backed",
            "inputs": {
                "private_key_out": self.private_path,
                "public_key_out": self.public_path,
            },
            "result": {
                "algorithm": self.result.algorithm,
                "standard": self.result.standard,
                "public_fingerprint_sha256": self.result.public_fingerprint_sha256,
                "private_format": self.result.private_format,
                "public_format": self.result.public_format,
                "private_encrypted": self.result.private_encrypted,
                "library": self.result.library,
            },
            "trace": [],
            "warnings": [PQC_BACKEND_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return (
            rf"\operatorname{{SHA256}}(PK_{{\text{{{self.result.algorithm}}}}})="
            rf"\mathtt{{{self.result.public_fingerprint_sha256}}}"
        )


@dataclass(frozen=True, slots=True)
class MLKEMEncapsulationView:
    """Render ML-KEM encapsulation."""

    result: MLKEMEncapsulationResult
    ciphertext_path: str | None
    shared_secret_path: str | None

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Ciphertext: {self.result.ciphertext_hex}")
        console.print(f"Shared secret: {self.result.shared_secret_hex}")
        if self.ciphertext_path is not None:
            console.print(f"Ciphertext written to: {self.ciphertext_path}")
        if self.shared_secret_path is not None:
            console.print(f"Shared secret written to: {self.shared_secret_path}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Parameter set", self.result.parameter_set)
            table.add_row("Standard", self.result.standard)
            table.add_row("Ciphertext length", f"{self.result.ciphertext_length_bytes} bytes")
            table.add_row("Shared-secret length", f"{self.result.shared_secret_length_bytes} bytes")
            table.add_row("Backend", self.result.library)
            console.print(table)
            console.print(f"Warning: {PQC_KEM_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.ml-kem.encapsulate",
            "implementation": "library-backed",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [PQC_KEM_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"|c|={self.result.ciphertext_length_bytes}\text{{ bytes}}",
            rf"|K|={self.result.shared_secret_length_bytes}\text{{ bytes}}",
        ]
        if explain:
            lines.append(r"\text{ML-KEM is a KEM, not bulk encryption}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class MLKEMDecapsulationView:
    """Render ML-KEM decapsulation."""

    result: MLKEMDecapsulationResult
    shared_secret_path: str | None

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Shared secret: {self.result.shared_secret_hex}")
        if self.shared_secret_path is not None:
            console.print(f"Shared secret written to: {self.shared_secret_path}")
        if explain:
            console.print(f"Parameter set: {self.result.parameter_set}")
            console.print(f"Ciphertext length: {self.result.ciphertext_length_bytes} bytes")
            console.print(f"Shared-secret length: {self.result.shared_secret_length_bytes} bytes")
            console.print(f"Backend: {self.result.library}")
            console.print(f"Warning: {PQC_KEM_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "post-quantum.ml-kem.decapsulate",
            "implementation": "library-backed",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [PQC_KEM_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"|K|={self.result.shared_secret_length_bytes}\text{{ bytes}}"


@dataclass(frozen=True, slots=True)
class PQCSignatureView:
    """Render ML-DSA or SLH-DSA signature generation."""

    result: MLDSASignatureResult | SLHDSASignatureResult
    source_kind: str
    signature_path: str | None

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.signature_hex)
        if self.signature_path is not None:
            console.print(f"Signature written to: {self.signature_path}")
        if explain:
            table = Table("Property", "Value")
            table.add_row("Algorithm", self.result.parameter_set)
            table.add_row("Standard", self.result.standard)
            table.add_row("Message source", self.source_kind)
            table.add_row("Message length", f"{len(bytes.fromhex(self.result.message_hex))} bytes")
            table.add_row("Context length", f"{len(bytes.fromhex(self.result.context_hex))} bytes")
            table.add_row("Signature length", f"{self.result.signature_length_bytes} bytes")
            table.add_row("Public fingerprint", self.result.public_fingerprint_sha256)
            table.add_row("Backend", self.result.library)
            console.print(table)
            console.print("The primitive signs the message; it does not encrypt it.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"post-quantum.{self.result.parameter_set.lower()}.sign",
            "implementation": "library-backed",
            "inputs": {"message_source": self.source_kind},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"|\sigma|={self.result.signature_length_bytes}\text{{ bytes}}"]
        if explain:
            lines.append(rf"\text{{{self.result.parameter_set}, {self.result.standard}}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class PQCVerificationView:
    """Render ML-DSA or SLH-DSA verification."""

    result: MLDSAVerificationResult | SLHDSAVerificationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Signature valid: {self.result.valid}")
        if explain:
            console.print(f"Algorithm: {self.result.parameter_set}")
            console.print(f"Context: {self.result.context_hex or '(empty)'}")
            console.print(f"Backend: {self.result.library}")
            console.print(f"Warning: {PQC_IDENTITY_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"post-quantum.{self.result.parameter_set.lower()}.verify",
            "implementation": "library-backed",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [PQC_IDENTITY_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{Verify}}={str(self.result.valid).lower()}"


@dataclass(frozen=True, slots=True)
class PQCComparisonView:
    """Render a classical/post-quantum comparison table."""

    command: str
    profiles: tuple[PQCComparisonProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Construction", "Role", "Family", "Standard", "Quantum status")
        for profile in self.profiles:
            table.add_row(
                profile.construction,
                profile.role,
                profile.family,
                profile.standard,
                profile.quantum_status,
            )
        console.print(table)
        if explain:
            for profile in self.profiles:
                console.print(f"{profile.construction}: {profile.principal_tradeoff}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": self.command,
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return "\\\n".join(
            rf"\text{{{p.construction}}}&\text{{{p.role}}}&\text{{{p.quantum_status}}}"
            for p in self.profiles
        )
