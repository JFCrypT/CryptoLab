#!/usr/bin/env bash
set -euo pipefail

# Install an isolated OpenSSL 3.5 LTS backend for CryptoLab PQC commands.
# The operating-system OpenSSL is never replaced or modified.

OPENSSL_VERSION="3.5.7"
OPENSSL_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
OPENSSL_ARCHIVE="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_ARCHIVE}"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
INSTALL_ROOT="${CRYPTOLAB_PQC_OPENSSL_ROOT:-${DATA_HOME}/cryptolab/openssl}"
INSTALL_DIR="${INSTALL_ROOT}/${OPENSSL_VERSION}"
CURRENT_LINK="${INSTALL_ROOT}/current"
FORCE=0

usage() {
    cat <<'TXT'
Usage: scripts/install_pqc_backend.sh [--force]

Install the OpenSSL 3.5 LTS backend used by CryptoLab's standardized PQC commands.
The backend is installed under the current user's data directory and never replaces
/usr/bin/openssl or operating-system OpenSSL libraries.

Options:
  --force   Rebuild the isolated backend even when a ready backend is already available.
  --help    Show this help message.
TXT
}

while (($#)); do
    case "$1" in
        --force)
            FORCE=1
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

version_is_35_or_newer() {
    local executable="$1"
    local version_line version major minor

    version_line="$($executable version 2>/dev/null || true)"
    version="$(printf '%s\n' "$version_line" | sed -nE 's/^OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+).*/\1.\2.\3/p')"
    [[ -n "$version" ]] || return 1

    IFS=. read -r major minor _ <<<"$version"
    (( major > 3 || (major == 3 && minor >= 5) ))
}

pqc_backend_ready() {
    local executable="$1"
    local kem signatures name

    [[ -x "$executable" ]] || return 1
    version_is_35_or_newer "$executable" || return 1

    kem="$($executable list -kem-algorithms 2>/dev/null || true)"
    signatures="$($executable list -signature-algorithms 2>/dev/null || true)"

    for name in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
        grep -Fq "$name" <<<"$kem" || return 1
    done

    for name in ML-DSA-44 ML-DSA-65 ML-DSA-87; do
        grep -Fq "$name" <<<"$signatures" || return 1
    done

    for name in \
        SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f \
        SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f \
        SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f \
        SLH-DSA-SHAKE-128s SLH-DSA-SHAKE-128f \
        SLH-DSA-SHAKE-192s SLH-DSA-SHAKE-192f \
        SLH-DSA-SHAKE-256s SLH-DSA-SHAKE-256f; do
        grep -Fq "$name" <<<"$signatures" || return 1
    done
}

find_ready_backend() {
    local candidate=""

    if [[ -n "${CRYPTOLAB_OPENSSL:-}" ]]; then
        if [[ "${CRYPTOLAB_OPENSSL}" == */* ]]; then
            candidate="${CRYPTOLAB_OPENSSL/#\~/$HOME}"
        else
            candidate="$(command -v "${CRYPTOLAB_OPENSSL}" 2>/dev/null || true)"
        fi
        if [[ -n "$candidate" ]] && pqc_backend_ready "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi

    for candidate in \
        "${CURRENT_LINK}/bin/openssl" \
        "/opt/openssl-3.5/bin/openssl" \
        "$(command -v openssl 2>/dev/null || true)"; do
        if [[ -n "$candidate" ]] && pqc_backend_ready "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

ensure_build_tools() {
    local missing=()
    local command_name

    for command_name in make perl tar sha256sum; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        missing+=("C compiler")
    fi
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing+=("curl/wget")
    fi

    if ((${#missing[@]} == 0)); then
        return 0
    fi

    echo "Missing build prerequisites: ${missing[*]}"
    if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
        echo "Installing required build tools through apt. The operating-system OpenSSL will not be changed."
        sudo apt-get update
        sudo apt-get install -y build-essential perl ca-certificates curl tar
        return 0
    fi

    echo "Install a C compiler, make, perl, tar, sha256sum, and curl or wget, then rerun this script." >&2
    exit 3
}

download_archive() {
    local destination="$1"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --proto '=https' --tlsv1.2 --output "$destination" "$OPENSSL_URL"
    else
        wget --https-only --output-document="$destination" "$OPENSSL_URL"
    fi
}

echo "CryptoLab PQC backend installer"
echo "OpenSSL target: ${OPENSSL_VERSION}"
echo "Install root:   ${INSTALL_ROOT}"
echo "System OpenSSL is not replaced or modified."
echo

if ((FORCE == 0)); then
    if ready="$(find_ready_backend)"; then
        echo "A compatible standardized PQC backend is already available:"
        "$ready" version
        echo "Executable: $ready"
        exit 0
    fi
fi

ensure_build_tools
mkdir -p "$INSTALL_ROOT"

if [[ -d "$INSTALL_DIR" ]]; then
    echo "Removing incomplete or forced installation: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
fi

work_dir="$(mktemp -d -t cryptolab-openssl-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT
archive_path="${work_dir}/${OPENSSL_ARCHIVE}"

echo "Downloading ${OPENSSL_ARCHIVE} from the OpenSSL project..."
download_archive "$archive_path"

echo "Verifying SHA-256..."
printf '%s  %s\n' "$OPENSSL_SHA256" "$archive_path" | sha256sum --check --status

echo "Extracting source..."
tar -xzf "$archive_path" -C "$work_dir"
cd "${work_dir}/openssl-${OPENSSL_VERSION}"

echo "Configuring isolated static OpenSSL build..."
./Configure \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR/ssl" \
    no-shared

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
echo "Building with ${jobs} parallel job(s)..."
make -j"$jobs"

echo "Running the upstream OpenSSL test suite..."
make test

echo "Installing under the user-local CryptoLab data directory..."
make install_sw

if ! pqc_backend_ready "${INSTALL_DIR}/bin/openssl"; then
    echo "Installed OpenSSL does not expose the complete standardized PQC backend." >&2
    exit 4
fi

ln -sfn "$OPENSSL_VERSION" "$CURRENT_LINK"

echo
echo "CryptoLab PQC backend installed successfully."
"${CURRENT_LINK}/bin/openssl" version
echo "Executable: ${CURRENT_LINK}/bin/openssl"
echo "ML-KEM:     available"
echo "ML-DSA:     available"
echo "SLH-DSA:    available"
echo
echo "CryptoLab detects this backend automatically; no shell environment variable is required."
