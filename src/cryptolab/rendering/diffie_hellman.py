"""Presentation objects for educational finite-field Diffie-Hellman."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.public_key.diffie_hellman import DHExchangeResult, DHGroupResult
from cryptolab.rendering.common import dataclass_to_dict

EDUCATIONAL_DH_WARNING = (
    "These small finite-field parameters are for inspection only and are not secure."
)
UNAUTHENTICATED_DH_WARNING = (
    "Finite-field Diffie-Hellman establishes a shared secret but does not authenticate the "
    "participants by itself."
)


@dataclass(frozen=True, slots=True)
class DHGroupView:
    """Render a small prime-field group and generator checks."""

    result: DHGroupResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Property", "Value")
        table.add_row("Prime modulus p", str(self.result.prime))
        table.add_row("Candidate generator g", str(self.result.generator))
        table.add_row("Group", f"Z_{self.result.prime}^*")
        table.add_row("Group order", str(self.result.group_order))
        table.add_row("Element order ord(g)", str(self.result.generator_order))
        table.add_row("Generator", str(self.result.is_generator))
        console.print(table)

        checks = Table("Prime factor q of p-1", "Exponent (p-1)/q", "Value", "Passes")
        for check in self.result.generator_checks:
            checks.add_row(
                str(check.prime_factor),
                str(check.exponent),
                str(check.value),
                str(check.passes),
            )
        console.print(checks)
        if explain:
            console.print(
                "A generator has order p-1. For every prime factor q of p-1, "
                "g^((p-1)/q) mod p must differ from 1."
            )
            console.print(
                "The security assumption is related to the discrete logarithm problem: "
                "recovering a from A = g^a mod p."
            )
            console.print(f"Warning: {EDUCATIONAL_DH_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.dh.group",
            "implementation": "educational",
            "inputs": {
                "prime": self.result.prime,
                "generator": self.result.generator,
            },
            "result": {
                "group_order": self.result.group_order,
                "generator_order": self.result.generator_order,
                "is_prime_modulus": self.result.is_prime_modulus,
                "is_generator": self.result.is_generator,
                "generator_checks": [
                    dataclass_to_dict(check) for check in self.result.generator_checks
                ],
            },
            "trace": [],
            "warnings": [EDUCATIONAL_DH_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        checks = r" \\ ".join(
            rf"q={check.prime_factor}:g^{{{check.exponent}}}\bmod "
            rf"{self.result.prime}={check.value}"
            for check in self.result.generator_checks
        )
        lines = [
            rf"p={self.result.prime},\quad g={self.result.generator},\quad "
            rf"\operatorname{{ord}}(g)={self.result.generator_order}",
            rf"\begin{{array}}{{l}}{checks}\end{{array}}",
        ]
        if explain:
            lines.append(r"\operatorname{ord}(g)=p-1\Longleftrightarrow g\text{ is a generator}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class DHExchangeView:
    """Render one educational Diffie-Hellman exchange and HKDF derivation."""

    result: DHExchangeResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table("Party", "Private exponent", "Public value", "Public-value order")
        table.add_row(
            "Alice",
            str(self.result.alice_private),
            str(self.result.alice_public),
            str(self.result.alice_public_order),
        )
        table.add_row(
            "Bob",
            str(self.result.bob_private),
            str(self.result.bob_public),
            str(self.result.bob_public_order),
        )
        console.print(table)
        console.print(
            f"Alice shared secret: {self.result.alice_shared_secret}; "
            f"Bob shared secret: {self.result.bob_shared_secret}"
        )
        console.print(f"Shared secret matches: {self.result.shared_secret_matches}")
        console.print(f"Raw shared-secret bytes: {self.result.shared_secret_hex}")
        console.print(f"HKDF-SHA-256 session key: {self.result.hkdf.okm_hex}")
        if explain:
            console.print(
                f"A = {self.result.group.generator}^{self.result.alice_private} mod "
                f"{self.result.group.prime} = {self.result.alice_public}"
            )
            console.print(
                f"B = {self.result.group.generator}^{self.result.bob_private} mod "
                f"{self.result.group.prime} = {self.result.bob_public}"
            )
            console.print(
                f"s_A = B^a mod p = {self.result.alice_shared_secret}; "
                f"s_B = A^b mod p = {self.result.bob_shared_secret}"
            )
            console.print(
                "The raw group element is encoded as fixed-width unsigned big-endian bytes "
                "and passed to HKDF-SHA-256."
            )
            console.print("Diffie-Hellman is key agreement, not encryption.")
            console.print(f"Warning: {UNAUTHENTICATED_DH_WARNING}")
            console.print(f"Warning: {EDUCATIONAL_DH_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        traces = []
        if explain:
            traces = [
                {
                    "operation": "alice-public",
                    "steps": [dataclass_to_dict(step) for step in self.result.alice_public_steps],
                },
                {
                    "operation": "bob-public",
                    "steps": [dataclass_to_dict(step) for step in self.result.bob_public_steps],
                },
                {
                    "operation": "alice-shared",
                    "steps": [dataclass_to_dict(step) for step in self.result.alice_shared_steps],
                },
                {
                    "operation": "bob-shared",
                    "steps": [dataclass_to_dict(step) for step in self.result.bob_shared_steps],
                },
            ]
        return {
            "schema_version": "1.0",
            "command": "public-key.dh.exchange",
            "implementation": "educational",
            "inputs": {
                "prime": self.result.group.prime,
                "generator": self.result.group.generator,
                "alice_private": self.result.alice_private,
                "bob_private": self.result.bob_private,
                "hkdf_info_hex": self.result.hkdf.info_hex,
                "hkdf_output_length": self.result.hkdf.output_length,
            },
            "result": {
                "alice_public": self.result.alice_public,
                "bob_public": self.result.bob_public,
                "alice_public_order": self.result.alice_public_order,
                "bob_public_order": self.result.bob_public_order,
                "alice_shared_secret": self.result.alice_shared_secret,
                "bob_shared_secret": self.result.bob_shared_secret,
                "shared_secret_matches": self.result.shared_secret_matches,
                "shared_secret_hex": self.result.shared_secret_hex,
                "hkdf": dataclass_to_dict(self.result.hkdf),
            },
            "trace": traces,
            "warnings": [UNAUTHENTICATED_DH_WARNING, EDUCATIONAL_DH_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"A={self.result.group.generator}^{{{self.result.alice_private}}}\bmod "
            rf"{self.result.group.prime}={self.result.alice_public}",
            rf"B={self.result.group.generator}^{{{self.result.bob_private}}}\bmod "
            rf"{self.result.group.prime}={self.result.bob_public}",
            rf"s=B^{{{self.result.alice_private}}}\bmod p="
            rf"A^{{{self.result.bob_private}}}\bmod p={self.result.alice_shared_secret}",
            rf"\operatorname{{HKDF\text{{-}}SHA256}}(s)=\mathtt{{{self.result.hkdf.okm_hex}}}",
        ]
        if explain:
            lines.append(r"\text{Unauthenticated Diffie-Hellman does not authenticate peers.}")
        return "\\\n".join(lines)
