"""Presentation objects for X25519 and Ed25519."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.public_key.modern_curves import (
    CurveKeyPairMaterial,
    Ed25519SignatureResult,
    Ed25519VerificationResult,
    KeyAgreementProfile,
    SignatureProfile,
    X25519ExchangeResult,
)
from cryptolab.rendering.common import dataclass_to_dict

X25519_AUTHENTICATION_WARNING = "X25519 does not authenticate either participant by itself."
ED25519_IDENTITY_WARNING = (
    "A valid Ed25519 signature proves possession of a private key, not a real-world identity."
)


@dataclass(frozen=True, slots=True)
class CurveKeyGenerationView:
    """Render generated modern curve key material without exposing the private key."""

    result: CurveKeyPairMaterial
    private_path: str
    public_path: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Property", "Value")
        table.add_row("Algorithm", self.result.algorithm)
        table.add_row("Private-key path", self.private_path)
        table.add_row("Public-key path", self.public_path)
        table.add_row("Public key (raw hex)", self.result.public_key_hex)
        table.add_row("Public fingerprint (SHA-256)", self.result.public_fingerprint_sha256)
        table.add_row("Private format", self.result.private_format)
        table.add_row("Public format", self.result.public_format)
        console.print(table)
        if explain:
            console.print("The private key is written with mode 0600; the public key uses 0644.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"public-key.{self.result.algorithm.lower()}.generate",
            "implementation": "library-backed",
            "inputs": {
                "private_key_out": self.private_path,
                "public_key_out": self.public_path,
            },
            "result": {
                "algorithm": self.result.algorithm,
                "public_key_hex": self.result.public_key_hex,
                "public_fingerprint_sha256": self.result.public_fingerprint_sha256,
                "private_format": self.result.private_format,
                "public_format": self.result.public_format,
                "private_encrypted": self.result.private_encrypted,
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return (
            rf"\text{{{self.result.algorithm} public key}}="
            rf"\mathtt{{{self.result.public_key_hex}}}"
        )


@dataclass(frozen=True, slots=True)
class X25519ExchangeView:
    """Render a local two-party X25519 exchange."""

    result: X25519ExchangeResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Party", "Public key", "Shared secret")
        table.add_row("Alice", self.result.alice_public_hex, self.result.alice_shared_secret_hex)
        table.add_row("Bob", self.result.bob_public_hex, self.result.bob_shared_secret_hex)
        console.print(table)
        console.print(f"Shared secret matches: {self.result.shared_secret_matches}")
        console.print(f"All-zero shared secret: {self.result.all_zero_shared_secret}")
        console.print(f"HKDF-SHA-256 session key: {self.result.hkdf.okm_hex}")
        if explain:
            console.print("Each side combines its private key with the peer public key.")
            console.print("The 32-byte raw shared secret is input keying material for HKDF.")
            console.print(f"Warning: {X25519_AUTHENTICATION_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.x25519.exchange",
            "implementation": "library-backed",
            "inputs": {},
            "result": {
                "alice_public_hex": self.result.alice_public_hex,
                "bob_public_hex": self.result.bob_public_hex,
                "alice_shared_secret_hex": self.result.alice_shared_secret_hex,
                "bob_shared_secret_hex": self.result.bob_shared_secret_hex,
                "shared_secret_matches": self.result.shared_secret_matches,
                "all_zero_shared_secret": self.result.all_zero_shared_secret,
                "hkdf": dataclass_to_dict(self.result.hkdf),
                "library": self.result.library,
            },
            "trace": [],
            "warnings": [X25519_AUTHENTICATION_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"K_A=K_B=\mathtt{{{self.result.alice_shared_secret_hex}}}",
            rf"\operatorname{{HKDF\text{{-}}SHA256}}(K)="
            rf"\mathtt{{{self.result.hkdf.okm_hex}}}",
        ]
        if explain:
            lines.append(r"\text{X25519 alone does not authenticate peers}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class Ed25519SignatureView:
    """Render one Ed25519 signature."""

    result: Ed25519SignatureResult
    source_kind: str

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.signature_hex)
        if explain:
            table = Table("Property", "Value")
            table.add_row("Algorithm", "Ed25519")
            table.add_row("Message source", self.source_kind)
            table.add_row("Message length", f"{len(bytes.fromhex(self.result.message_hex))} bytes")
            table.add_row("Signature length", f"{self.result.signature_length_bytes} bytes")
            table.add_row("Public key", self.result.public_key_hex)
            table.add_row("Deterministic", str(self.result.deterministic))
            table.add_row("Library", self.result.library)
            console.print(table)
            console.print("Ed25519 signs; it does not encrypt the message.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ed25519.sign",
            "implementation": "library-backed",
            "inputs": {"message_source": self.source_kind},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"\sigma=\mathtt{{{self.result.signature_hex}}}"]
        if explain:
            lines.append(r"|\sigma|=64\text{ bytes}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class Ed25519VerificationView:
    """Render Ed25519 signature verification."""

    result: Ed25519VerificationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Signature valid: {self.result.valid}")
        if explain:
            console.print(f"Public key: {self.result.public_key_hex}")
            console.print(f"Warning: {ED25519_IDENTITY_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ed25519.verify",
            "implementation": "library-backed",
            "inputs": {},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [ED25519_IDENTITY_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{Verify}}_{{Ed25519}}={str(self.result.valid).lower()}"


@dataclass(frozen=True, slots=True)
class KeyAgreementComparisonView:
    """Render finite-field Diffie-Hellman versus X25519."""

    profiles: tuple[KeyAgreementProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table(
            "Construction",
            "Category",
            "Mathematical setting",
            "Public value",
            "Authentication",
        )
        for profile in self.profiles:
            table.add_row(
                profile.construction,
                profile.category,
                profile.mathematical_setting,
                profile.public_value,
                profile.authentication,
            )
        console.print(table)
        if explain:
            details = Table("Construction", "Shared-secret processing", "Limitation")
            for profile in self.profiles:
                details.add_row(
                    profile.construction,
                    profile.shared_secret_processing,
                    profile.principal_limitation,
                )
            console.print(details)
            console.print("Neither construction authenticates participants by itself.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.compare-key-agreement",
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = " \\ ".join(
            rf"\text{{{profile.construction}}}&\text{{{profile.category}}}"
            for profile in self.profiles
        )
        return rf"\begin{{array}}{{ll}}{rows}\end{{array}}"


@dataclass(frozen=True, slots=True)
class SignatureComparisonView:
    """Render RSA-PSS versus Ed25519 and distinguish signatures from HMAC."""

    profiles: tuple[SignatureProfile, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table(
            "Construction",
            "Category",
            "Key relationship",
            "Output size",
            "Randomized",
        )
        for profile in self.profiles:
            table.add_row(
                profile.construction,
                profile.category,
                profile.key_relationship,
                profile.output_size,
                profile.randomized,
            )
        console.print(table)
        if explain:
            details = Table("Construction", "Verification", "Principal limitation")
            for profile in self.profiles:
                details.add_row(
                    profile.construction,
                    profile.verification,
                    profile.principal_limitation,
                )
            console.print(details)
            console.print(
                "Digital signatures use distinct signing and verification keys; HMAC uses one "
                "shared secret and therefore does not provide technical non-repudiation."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.compare-signatures",
            "implementation": "comparison",
            "inputs": {},
            "result": [dataclass_to_dict(profile) for profile in self.profiles],
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        rows = " \\ ".join(
            rf"\text{{{profile.construction}}}&\text{{{profile.category}}}"
            for profile in self.profiles
        )
        return rf"\begin{{array}}{{ll}}{rows}\end{{array}}"
