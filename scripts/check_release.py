#!/usr/bin/env python3
"""Validate CryptoLab release metadata, scope, documentation, and distributions."""

from __future__ import annotations

import argparse
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path

EXPECTED_VERSION = "1.0.0"
APPROVED_LAB_FILES = {
    "__init__.py",
    "caesar_brute_force.py",
    "dh_man_in_the_middle.py",
    "ecb_pattern_leakage.py",
    "models.py",
    "vernam_key_reuse.py",
}
REQUIRED_FILES = {
    ".github/workflows/ci.yml",
    ".github/workflows/sagemath-cross-validation.yml",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docs/comparisons/required-comparisons.md",
    "docs/foundations/cryptographic-foundations.md",
    "docs/release-process.md",
    "docs/validation/release-acceptance.md",
    "docs/validation/release-traceability.md",
    "docs/validation/sagemath-cross-validation.md",
    "sagemath/README.md",
    "sagemath/compute_reference.py",
    "scripts/cross_validate.py",
}
FORBIDDEN_PATHS = {
    "src/cryptolab/ai",
    "src/cryptolab/database",
    "src/cryptolab/gui",
    "src/cryptolab/iot",
    "src/cryptolab/pki",
    "src/cryptolab/pqc",
    "src/cryptolab/server",
    "src/cryptolab/telemetry",
    "src/cryptolab/tls",
    "src/cryptolab/web",
}
TEXT_SUFFIXES = {".cff", ".md", ".py", ".toml", ".yaml", ".yml"}
PLACEHOLDER_PATTERN = re.compile(r"\b(?:FIXME|TBD|TO\s*DO)\b", re.IGNORECASE)


class ReleaseCheckError(RuntimeError):
    """Raised when one release-readiness assertion fails."""


def require(condition: bool, message: str) -> None:  # noqa: FBT001
    """Raise a release-check error when *condition* is false."""

    if not condition:
        raise ReleaseCheckError(message)


def read_project_version(root: Path) -> str:
    """Read the project version from pyproject.toml."""

    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    version = project["version"]
    require(isinstance(version, str), "project.version must be a string")
    return version


def read_python_version(root: Path) -> str:
    """Read the package version constant without importing the package."""

    metadata = (root / "src/cryptolab/metadata.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"$', metadata, re.MULTILINE)
    require(match is not None, "src/cryptolab/metadata.py has no version constant")
    return match.group(1)


def read_citation_version(root: Path) -> str:
    """Read the version field from CITATION.cff."""

    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    match = re.search(r"^version:\s*([^\s]+)$", citation, re.MULTILINE)
    require(match is not None, "CITATION.cff has no version field")
    return match.group(1).strip('"')


def check_repository(root: Path) -> list[str]:
    """Run static repository and metadata checks."""

    messages: list[str] = []
    for relative in sorted(REQUIRED_FILES):
        require((root / relative).is_file(), f"missing required file: {relative}")
    messages.append(f"required files: {len(REQUIRED_FILES)} present")

    versions = {
        read_project_version(root),
        read_python_version(root),
        read_citation_version(root),
    }
    require(
        versions == {EXPECTED_VERSION},
        f"inconsistent release versions: {sorted(versions)}",
    )
    messages.append(f"version consistency: {EXPECTED_VERSION}")

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    require(
        "## [1.0.0] - 2026-08-02" in changelog,
        "CHANGELOG.md has no dated 1.0.0 release section",
    )
    messages.append("changelog release section: present")

    roadmap = (root / "docs/roadmap.md").read_text(encoding="utf-8")
    require(
        "10. **Completed:**" in roadmap,
        "roadmap does not mark milestone 10 complete",
    )
    require(
        "**Next:**" not in roadmap,
        "roadmap still contains an unfinished Next milestone",
    )
    messages.append("roadmap: complete")

    lab_dir = root / "src/cryptolab/labs"
    actual_lab_files = {path.name for path in lab_dir.glob("*.py")}
    require(
        actual_lab_files == APPROVED_LAB_FILES,
        f"unexpected controlled-laboratory files: {sorted(actual_lab_files)}",
    )
    messages.append("controlled laboratory file set: exactly four approved laboratories")

    for relative in sorted(FORBIDDEN_PATHS):
        require(
            not (root / relative).exists(),
            f"forbidden scope path exists: {relative}",
        )
    messages.append("scope guardrails: no forbidden product-layer paths")

    source_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (root / "src").rglob("*.py")
    )
    require("sage.all" not in source_text, "normal package imports SageMath")
    require("import sage" not in source_text, "normal package imports SageMath")
    messages.append("SageMath isolation: normal package has no Sage imports")

    optional_documents = (
        root / "README.md",
        root / "CONTRIBUTING.md",
        root / "docs/release-process.md",
        root / "docs/validation/release-acceptance.md",
        root / "docs/validation/sagemath-cross-validation.md",
        root / "sagemath/README.md",
    )
    combined_optional_text = "\n".join(
        path.read_text(encoding="utf-8").lower() for path in optional_documents
    )
    require(
        "optional" in combined_optional_text,
        "documentation does not describe SageMath cross-validation as optional",
    )
    require(
        "scripts/cross_validate.py" in combined_optional_text,
        "documentation omits the dynamic cross-validation coordinator",
    )
    require(
        "sagemath/compute_reference.py" in combined_optional_text,
        "documentation omits the SageMath reference process",
    )
    messages.append("SageMath policy: optional dynamic direct cross-validation documented")

    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("release-readiness:" in workflow, "CI has no release-readiness job")
    require("if: ${{ always() }}" in workflow, "CI release gate can be skipped")
    require(
        "needs.quality.result" in workflow
        and "needs.tests.result" in workflow
        and "needs.package.result" in workflow,
        "CI release gate does not enforce all prerequisite jobs",
    )
    require(
        "sagemath/sagemath" not in workflow,
        "mandatory CI unexpectedly depends on a SageMath container",
    )
    optional_workflow = (root / ".github/workflows/sagemath-cross-validation.yml").read_text(
        encoding="utf-8"
    )
    require(
        "workflow_dispatch:" in optional_workflow,
        "optional SageMath workflow is not manually dispatchable",
    )
    require(
        "scripts/cross_validate.py" in optional_workflow
        and "sagemath/compute_reference.py" in optional_workflow,
        "optional SageMath workflow does not use the dynamic architecture",
    )
    messages.append("CI policy: mandatory CI is SageMath-free; optional workflow is available")

    ignored = {
        root / "scripts/check_release.py",
        root / "scripts/cross_validate.py",
        root / "sagemath/compute_reference.py",
    }
    placeholders: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES or path in ignored:
            continue
        if ".venv" in path.parts or "site" in path.parts or "dist" in path.parts:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            if PLACEHOLDER_PATTERN.search(line):
                placeholders.append(f"{path.relative_to(root)}:{line_number}")
    require(not placeholders, f"placeholder markers found: {', '.join(placeholders)}")
    messages.append("placeholder scan: clear")

    nav = (root / "mkdocs.yml").read_text(encoding="utf-8")
    for required_page in (
        "comparisons/required-comparisons.md",
        "foundations/cryptographic-foundations.md",
        "release-process.md",
        "validation/release-acceptance.md",
        "validation/release-traceability.md",
        "validation/sagemath-cross-validation.md",
    ):
        require(required_page in nav, f"MkDocs navigation omits {required_page}")
    messages.append("MkDocs navigation: release documentation included")

    return messages


def archive_members(path: Path) -> set[str]:
    """Return normalized member names from a wheel or source archive."""

    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return set(archive.namelist())
    with tarfile.open(path, "r:gz") as archive:
        return {member.name for member in archive.getmembers()}


def has_suffix(members: set[str], suffix: str) -> bool:
    """Return whether one archive member ends with *suffix*."""

    return any(member.endswith(suffix) for member in members)


def check_distributions(root: Path, dist_dir: Path) -> list[str]:
    """Validate built wheel and source-distribution contents."""

    messages: list[str] = []
    wheels = sorted(dist_dir.glob("cryptolab-*.whl"))
    sdists = sorted(dist_dir.glob("cryptolab-*.tar.gz"))
    require(len(wheels) == 1, f"expected one wheel, found {len(wheels)}")
    require(len(sdists) == 1, f"expected one source distribution, found {len(sdists)}")

    wheel_members = archive_members(wheels[0])
    for suffix in (
        "cryptolab/__init__.py",
        "cryptolab/cli/app.py",
        "cryptolab/data/alphabets/latin_upper.json",
        "cryptolab/data/alphabets/spanish_upper.json",
        "cryptolab/py.typed",
    ):
        require(has_suffix(wheel_members, suffix), f"wheel omits {suffix}")
    require(
        not any("/tests/" in member or member.startswith("tests/") for member in wheel_members),
        "wheel unexpectedly contains tests",
    )
    require(
        not any("sagemath/" in member for member in wheel_members),
        "wheel unexpectedly contains SageMath material",
    )
    messages.append(f"wheel content: {wheels[0].name} validated")

    sdist_members = archive_members(sdists[0])
    for suffix in (
        "README.md",
        "LICENSE",
        "docs/comparisons/required-comparisons.md",
        "docs/validation/release-acceptance.md",
        "sagemath/README.md",
        "sagemath/compute_reference.py",
        "scripts/cross_validate.py",
        "scripts/check_release.py",
    ):
        require(
            has_suffix(sdist_members, suffix),
            f"source distribution omits {suffix}",
        )
    messages.append(f"source distribution content: {sdists[0].name} validated")

    forbidden_suffixes = (".pem", ".key", ".p12", ".pfx")
    for member in wheel_members | sdist_members:
        require(
            not member.lower().endswith(forbidden_suffixes),
            f"key material in archive: {member}",
        )
    messages.append("distribution secret-file scan: clear")

    require(root.is_dir(), "repository root disappeared during distribution validation")
    return messages


def main() -> int:
    """Run release checks and return a process status."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        help="Validate one built wheel and one source distribution from this directory.",
    )
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        messages = check_repository(root)
        if arguments.dist_dir is not None:
            messages.extend(check_distributions(root, arguments.dist_dir.resolve()))
    except ReleaseCheckError as error:
        print(f"Release check failed: {error}")
        return 1

    print("CryptoLab release readiness checks")
    for message in messages:
        print(f"- PASS: {message}")
    print(f"Release candidate {EXPECTED_VERSION}: READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
