# Isolated OpenSSL PQC backend

CryptoLab 1.1.0 delegates standardized ML-KEM, ML-DSA, and SLH-DSA operations to
OpenSSL 3.5+ EVP. Many stable Linux distributions still provide an older system OpenSSL,
so CryptoLab can install its own isolated OpenSSL 3.5 LTS backend without replacing the
operating system's `/usr/bin/openssl` or shared libraries.

## Recommended installation

From a source checkout, the normal installation entry point is:

```bash
./scripts/install.sh
```

The installer synchronizes the locked Python environment and checks for a complete
standardized PQC backend. If no compatible backend is already available, it downloads the
pinned OpenSSL 3.5 LTS source release, verifies its SHA-256 checksum, builds it, runs the
upstream OpenSSL test suite, and installs it below the current user's data directory:

```text
~/.local/share/cryptolab/openssl/<version>/
~/.local/share/cryptolab/openssl/current -> <version>
```

No CryptoLab installation step overwrites `/usr/bin/openssl`, `libssl`, or `libcrypto`
managed by the operating system.

The isolated backend installer can also be run directly:

```bash
./scripts/install_pqc_backend.sh
```

If build prerequisites are missing on an `apt`-based Linux system, the script installs only
the required build tools through the package manager. The OpenSSL backend itself remains
user-local and isolated.

## Automatic backend selection

Standardized PQC commands resolve OpenSSL in this order:

1. an explicit executable supplied internally by CryptoLab;
2. `CRYPTOLAB_OPENSSL`, when the user intentionally overrides discovery;
3. `~/.local/share/cryptolab/openssl/current/bin/openssl`;
4. `/opt/openssl-3.5/bin/openssl`, for an administrator-managed isolated installation;
5. the first `openssl` executable on `PATH`.

The normal installation therefore requires no environment variable after the sandboxed
backend has been installed.

Inspect the selected executable and algorithm availability with:

```bash
uv run cryptolab --explain post-quantum backend
```

A complete backend reports all three ML-KEM parameter sets, all three ML-DSA parameter
sets, all twelve SLH-DSA parameter sets, and `PQC backend ready = True`.

## Manual override

Advanced users may select another compatible OpenSSL executable without changing the
operating system installation:

```bash
export CRYPTOLAB_OPENSSL=/path/to/openssl
uv run cryptolab --explain post-quantum backend
```

An invalid override is treated as an error rather than silently falling back to another
binary.

## Installing without PQC

The existing CryptoLab 1.0.0 functionality remains usable without an OpenSSL 3.5 PQC
backend. A source checkout can be prepared without installing the sandboxed backend:

```bash
./scripts/install.sh --without-pqc
```

In that mode, mathematics, classical cryptography, symmetric cryptography, hashing,
RSA, finite-field Diffie-Hellman, educational elliptic curves, X25519, Ed25519, and the four
controlled laboratories keep their existing behavior. Only standardized `post-quantum`
operations that require OpenSSL 3.5+ are unavailable.

## Security and reproducibility

The installer pins the OpenSSL 3.5 LTS source version and its expected SHA-256 digest.
The archive is downloaded over HTTPS and the digest is checked before extraction. The build
uses `no-shared` so the CryptoLab-specific executable does not depend on replacing the
operating system's OpenSSL shared libraries.

Release acceptance still requires native CI evidence for real ML-KEM, ML-DSA, and SLH-DSA
workflows. The local installer is an ergonomic deployment path, not a substitute for the
release-gated tests.
