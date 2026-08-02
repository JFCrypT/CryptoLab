from __future__ import annotations

import re
import tomllib
from pathlib import Path

from cryptolab.labs.models import APPROVED_LABS
from cryptolab.metadata import __version__

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_LABS = (
    "caesar-brute-force",
    "vernam-key-reuse",
    "ecb-pattern-leakage",
    "dh-man-in-the-middle",
)


def test_release_version_is_consistent() -> None:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project_version = tomllib.load(stream)["project"]["version"]
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    citation_match = re.search(r"^version:\s*([^\s]+)$", citation, re.MULTILINE)

    assert citation_match is not None
    citation_version = citation_match.group(1).strip('"')
    assert project_version == __version__ == citation_version == "1.0.0"


def test_exact_controlled_laboratory_registry() -> None:
    assert tuple(descriptor.identifier for descriptor in APPROVED_LABS) == EXPECTED_LABS
    assert all(descriptor.status == "implemented" for descriptor in APPROVED_LABS)


def test_release_documentation_exists() -> None:
    required = (
        "docs/comparisons/required-comparisons.md",
        "docs/foundations/cryptographic-foundations.md",
        "docs/release-process.md",
        "docs/validation/release-acceptance.md",
        "docs/validation/release-traceability.md",
        "docs/validation/sagemath-cross-validation.md",
    )
    assert all((ROOT / relative).is_file() for relative in required)


def test_sagemath_cross_validation_is_optional_dynamic_and_isolated() -> None:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        metadata = tomllib.load(stream)
    dependencies = metadata["project"]["dependencies"]
    source_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src").rglob("*.py")
    )
    acceptance = (ROOT / "docs/validation/release-acceptance.md").read_text(encoding="utf-8")
    coordinator = (ROOT / "scripts/cross_validate.py").read_text(encoding="utf-8")
    reference = (ROOT / "sagemath/compute_reference.py").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    optional_workflow = (ROOT / ".github/workflows/sagemath-cross-validation.yml").read_text(
        encoding="utf-8"
    )

    assert all("sage" not in dependency.lower() for dependency in dependencies)
    assert "sage.all" not in source_text
    assert "optional" in acceptance.lower()
    assert "scripts/cross_validate.py" in acceptance
    assert "sagemath/compute_reference.py" in acceptance
    assert "CANONICALIZERS" in coordinator
    assert "json.load(sys.stdin)" in reference
    assert not (ROOT / "sagemath/cross_validate.py").exists()
    assert "sagemath/sagemath" not in workflow
    assert "workflow_dispatch:" in optional_workflow
    assert "scripts/cross_validate.py" in optional_workflow


def test_roadmap_marks_complete_scope() -> None:
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    assert "10. **Completed:**" in roadmap
    assert "**Next:**" not in roadmap
