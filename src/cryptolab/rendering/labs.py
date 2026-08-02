"""Presentation objects for controlled cryptanalysis laboratories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.labs.caesar_brute_force import CaesarBruteForceLabResult
from cryptolab.labs.dh_man_in_the_middle import DHManInTheMiddleResult
from cryptolab.labs.ecb_pattern_leakage import ECBPatternLeakageResult
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


@dataclass(frozen=True, slots=True)
class ECBPatternLeakageLabView:
    """Render repeated-block leakage in the controlled AES-ECB laboratory."""

    result: ECBPatternLeakageResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        table = Table(
            "Block",
            "Plaintext",
            "Ciphertext",
            "Repeated plaintext",
            "Repeated ciphertext",
        )
        repeated_plaintext = set(self.result.repeated_plaintext_blocks)
        repeated_ciphertext = set(self.result.repeated_ciphertext_blocks)
        for block in self.result.blocks:
            table.add_row(
                str(block.index),
                block.plaintext_hex,
                block.ciphertext_hex,
                str(block.plaintext_hex in repeated_plaintext),
                str(block.ciphertext_hex in repeated_ciphertext),
            )
        console.print(table)
        console.print(f"Repeated pattern preserved: {self.result.repeated_pattern_preserved}")
        if explain:
            console.print(f"Violated assumption: {self.result.violated_assumption}")
            console.print(f"Security effect: {self.result.security_effect}")
            console.print(f"Mitigation: {self.result.mitigation}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "lab.ecb-pattern-leakage",
            "implementation": "controlled-laboratory",
            "inputs": {"plaintext_hex": self.result.plaintext_hex},
            "result": {
                "ciphertext_hex": self.result.ciphertext_hex,
                "block_count": self.result.block_count,
                "unique_plaintext_blocks": self.result.unique_plaintext_blocks,
                "unique_ciphertext_blocks": self.result.unique_ciphertext_blocks,
                "repeated_plaintext_blocks": self.result.repeated_plaintext_blocks,
                "repeated_ciphertext_blocks": self.result.repeated_ciphertext_blocks,
                "repeated_pattern_preserved": self.result.repeated_pattern_preserved,
                "blocks": [dataclass_to_dict(block) for block in self.result.blocks],
                "violated_assumption": self.result.violated_assumption,
                "security_effect": self.result.security_effect,
                "mitigation": self.result.mitigation,
            },
            "trace": [],
            "warnings": ["This laboratory uses deliberately vulnerable local AES-ECB data."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        rows = r" \\ ".join(
            rf"{block.index}&\mathtt{{{block.plaintext_hex}}}&\mathtt{{{block.ciphertext_hex}}}"
            for block in self.result.blocks
        )
        lines = [rf"\begin{{array}}{{rll}}i&P_i&C_i\\{rows}\end{{array}}"]
        if explain:
            lines.append(r"P_i=P_j\Longrightarrow C_i=C_j\quad\text{under ECB and one key}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class DHManInTheMiddleLabView:
    """Render the unauthenticated Diffie-Hellman man-in-the-middle laboratory."""

    result: DHManInTheMiddleResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        honest = Table("Honest value", "Result")
        honest.add_row("Alice public A", str(self.result.alice_public))
        honest.add_row("Bob public B", str(self.result.bob_public))
        honest.add_row("Honest shared secret", str(self.result.honest_shared_secret))
        console.print(honest)

        attack = Table("Channel", "Received public value", "Endpoint secret", "Mallory secret")
        attack.add_row(
            "Alice <-> Mallory",
            str(self.result.mallory_public_to_alice),
            str(self.result.alice_channel_secret),
            str(self.result.mallory_alice_secret),
        )
        attack.add_row(
            "Mallory <-> Bob",
            str(self.result.mallory_public_to_bob),
            str(self.result.bob_channel_secret),
            str(self.result.mallory_bob_secret),
        )
        console.print(attack)
        console.print(f"Mallory matches Alice: {self.result.alice_channel_matches}")
        console.print(f"Mallory matches Bob: {self.result.bob_channel_matches}")
        console.print(
            f"Alice and Bob now have different secrets: {self.result.alice_bob_secrets_differ}"
        )
        if explain:
            console.print(f"Alice-channel HKDF key: {self.result.alice_channel_key_hex}")
            console.print(f"Mallory copy for Alice: {self.result.mallory_alice_key_hex}")
            console.print(f"Bob-channel HKDF key: {self.result.bob_channel_key_hex}")
            console.print(f"Mallory copy for Bob: {self.result.mallory_bob_key_hex}")
            console.print(f"Violated assumption: {self.result.violated_assumption}")
            console.print(f"Security effect: {self.result.security_effect}")
            console.print(f"Mitigation: {self.result.mitigation}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "lab.dh-man-in-the-middle",
            "implementation": "controlled-laboratory",
            "inputs": {
                "prime": self.result.prime,
                "generator": self.result.generator,
                "alice_private": self.result.alice_private,
                "bob_private": self.result.bob_private,
                "mallory_alice_private": self.result.mallory_alice_private,
                "mallory_bob_private": self.result.mallory_bob_private,
            },
            "result": {
                "alice_public": self.result.alice_public,
                "bob_public": self.result.bob_public,
                "honest_shared_secret": self.result.honest_shared_secret,
                "mallory_public_to_alice": self.result.mallory_public_to_alice,
                "mallory_public_to_bob": self.result.mallory_public_to_bob,
                "alice_channel_secret": self.result.alice_channel_secret,
                "mallory_alice_secret": self.result.mallory_alice_secret,
                "bob_channel_secret": self.result.bob_channel_secret,
                "mallory_bob_secret": self.result.mallory_bob_secret,
                "alice_channel_matches": self.result.alice_channel_matches,
                "bob_channel_matches": self.result.bob_channel_matches,
                "alice_bob_secrets_differ": self.result.alice_bob_secrets_differ,
                "alice_channel_key_hex": self.result.alice_channel_key_hex,
                "mallory_alice_key_hex": self.result.mallory_alice_key_hex,
                "bob_channel_key_hex": self.result.bob_channel_key_hex,
                "mallory_bob_key_hex": self.result.mallory_bob_key_hex,
                "violated_assumption": self.result.violated_assumption,
                "security_effect": self.result.security_effect,
                "mitigation": self.result.mitigation,
            },
            "trace": [],
            "warnings": ["This laboratory uses deliberately vulnerable local parameters."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"K_{{A,M}}={self.result.alice_channel_secret}=K_{{M,A}}",
            rf"K_{{B,M}}={self.result.bob_channel_secret}=K_{{M,B}}",
            r"K_{A,M}\ne K_{B,M}",
        ]
        if explain:
            lines.append(r"\text{The exchanged public values were not authenticated.}")
        return "\\\n".join(lines)
