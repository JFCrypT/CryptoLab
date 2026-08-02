"""Shared models for the approved controlled cryptanalysis laboratories."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LabDescriptor:
    """One approved controlled laboratory and its implementation status."""

    identifier: str
    title: str
    status: str


APPROVED_LABS = (
    LabDescriptor("caesar-brute-force", "Caesar brute force", "implemented"),
    LabDescriptor("vernam-key-reuse", "Vernam key reuse", "implemented"),
    LabDescriptor("ecb-pattern-leakage", "ECB pattern leakage", "implemented"),
    LabDescriptor("dh-man-in-the-middle", "Diffie-Hellman man-in-the-middle", "implemented"),
)
