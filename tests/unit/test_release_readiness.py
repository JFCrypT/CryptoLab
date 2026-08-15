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
    assert project_version == __version__ == citation_version == "1.1.0"


def test_exact_controlled_laboratory_registry() -> None:
    assert tuple(descriptor.identifier for descriptor in APPROVED_LABS) == EXPECTED_LABS
    assert all(descriptor.status == "implemented" for descriptor in APPROVED_LABS)


def test_release_documentation_exists() -> None:
    required = (
        "docs/comparisons/required-comparisons.md",
        "docs/foundations/cryptographic-foundations.md",
        "docs/post-quantum/overview.md",
        "docs/post-quantum/backend.md",
        "docs/post-quantum/ml-kem.md",
        "docs/post-quantum/ml-dsa.md",
        "docs/post-quantum/slh-dsa.md",
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
    assert "11. **Completed:**" in roadmap
    assert "**Next:**" not in roadmap


def test_post_quantum_release_scope_is_standardized_and_library_backed() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "src/cryptolab/post_quantum").glob("*.py")
    )
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "FIPS 203" in source
    assert "ML-KEM" in source
    assert "FIPS 204" in source
    assert "ML-DSA" in source
    assert "FIPS 205" in source
    assert "SLH-DSA" in source
    assert "OpenSSL 3.5" in source
    assert "pqc-native:" in workflow
    assert "ubuntu-26.04" in workflow
    assert "needs.pqc-native.result" in workflow


def test_pqc_backend_installation_is_isolated_and_documented() -> None:
    installer = (ROOT / "scripts/install_pqc_backend.sh").read_text(encoding="utf-8")
    general_installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    backend_docs = (ROOT / "docs/post-quantum/backend.md").read_text(encoding="utf-8")
    backend_source = (ROOT / "src/cryptolab/post_quantum/openssl_backend.py").read_text(
        encoding="utf-8"
    )

    assert 'OPENSSL_VERSION="3.5.7"' in installer
    assert "OPENSSL_SHA256=" in installer
    assert "no-shared" in installer
    assert "install_pqc_backend.sh" in general_installer
    assert ".local/share/cryptolab/openssl" in backend_docs
    assert "/usr/bin/openssl" in backend_docs
    assert "cryptolab/openssl/current/bin/openssl" in backend_source
