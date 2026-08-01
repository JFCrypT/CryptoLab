"""One-Time Pad requirements and limitations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OTPRequirement:
    """One necessary One-Time Pad condition."""

    identifier: str
    requirement: str
    rationale: str


def otp_requirements() -> tuple[OTPRequirement, ...]:
    """Return the complete set of project-defined One-Time Pad requirements."""

    return (
        OTPRequirement(
            "uniform-random-key",
            "The key must be uniformly random.",
            "Predictable or biased key material invalidates the information-theoretic model.",
        ),
        OTPRequirement(
            "key-length",
            "The key must be at least as long as the message.",
            "Every message symbol requires independent key material.",
        ),
        OTPRequirement(
            "one-time-use",
            "The key must be used exactly once.",
            "Reuse reveals the XOR of the corresponding plaintexts.",
        ),
        OTPRequirement(
            "secure-distribution",
            "The key must be distributed securely.",
            "An adversary who obtains the key obtains the plaintext.",
        ),
        OTPRequirement(
            "secure-storage",
            "The key must be stored securely before use.",
            "Stored key exposure destroys confidentiality.",
        ),
        OTPRequirement(
            "secure-destruction",
            "The key must be destroyed securely after use.",
            "Residual copies can reveal previously protected plaintext.",
        ),
    )
