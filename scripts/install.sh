#!/usr/bin/env bash
set -euo pipefail

INSTALL_PQC=1
SYNC=1

usage() {
    cat <<'TXT'
Usage: scripts/install.sh [--without-pqc] [--skip-sync]

Prepare a CryptoLab source checkout for local use.

By default the installer synchronizes the locked Python environment and ensures that a
sandboxed OpenSSL 3.5 LTS backend is available for standardized PQC commands.

Options:
  --without-pqc  Prepare CryptoLab without installing the optional local PQC backend.
  --skip-sync    Do not run `uv sync --locked`.
  --help         Show this help message.
TXT
}

while (($#)); do
    case "$1" in
        --without-pqc)
            INSTALL_PQC=0
            ;;
        --skip-sync)
            SYNC=0
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "CryptoLab 1.1.0 supports Linux source installation." >&2
    exit 3
fi

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required. Install uv, then rerun scripts/install.sh." >&2
    exit 3
fi

echo "CryptoLab 1.1.0 installer"
echo "Repository: $ROOT"
echo

if ((SYNC == 1)); then
    echo "Synchronizing the locked Python environment..."
    uv sync --locked
fi

if ((INSTALL_PQC == 1)); then
    echo
    "$ROOT/scripts/install_pqc_backend.sh"
fi

echo
echo "Verifying CryptoLab..."
uv run cryptolab --version

if ((INSTALL_PQC == 1)); then
    echo
    uv run cryptolab --explain post-quantum backend
fi

echo
echo "Installation completed."
echo "Run: uv run cryptolab --help"
