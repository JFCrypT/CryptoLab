# ADR 0012: Standardized post-quantum cryptography conventions

## Status

Accepted for CryptoLab 1.1.0.

## Decision

CryptoLab adds the final NIST FIPS post-quantum primitives ML-KEM (FIPS 203), ML-DSA
(FIPS 204), and SLH-DSA (FIPS 205).

The standardized primitives are `library-backed` and use OpenSSL 3.5+ EVP. CryptoLab does
not provide an independent production reimplementation of these FIPS algorithms.

The public command group is `cryptolab post-quantum`. It contains:

- bounded educational polynomial-ring and LWE-style examples;
- all three ML-KEM parameter sets;
- all three ML-DSA parameter sets;
- all twelve SLH-DSA SHA-2/SHAKE parameter sets;
- classical/post-quantum comparisons;
- backend inspection.

Private keys are written as unencrypted PKCS#8 PEM with restrictive permissions. Public keys
are written as SubjectPublicKeyInfo PEM. The displayed FIPS size tables refer to raw
standardized key/signature/ciphertext sizes, not PEM sizes.

Pure ML-DSA and SLH-DSA signatures may use an optional context of at most 255 bytes.
ML-KEM output is treated as key material; CryptoLab does not present the KEM ciphertext as
bulk message encryption.

## Educational boundary

Tiny polynomial and LWE-style calculations are educational examples only. They are bounded
and explicitly separated from standardized primitives. CryptoLab does not add lattice
cryptanalysis, LLL/BKZ attack tooling, an LWE solver, a quantum simulator, Shor's algorithm,
or Grover's algorithm.

## Scope boundary

No new controlled attack laboratory is added. The registry remains exactly the same four
laboratories accepted for 1.0.0.

HQC, FN-DSA/Falcon, Classic McEliece, BIKE, FrodoKEM, NTRU, PQC TLS, PQC X.509, PKI,
hybrid network protocols, and OpenSSL-provider development are outside version 1.1.0.

## Backend availability

Standardized PQC commands require OpenSSL 3.5+ with the algorithms exposed through EVP.
The source installer may provision a pinned, user-local OpenSSL 3.5 LTS build under the
CryptoLab data directory when the operating-system OpenSSL is unsuitable. It MUST NOT
replace the operating-system OpenSSL executable or shared libraries. Runtime discovery
prefers an explicit `CRYPTOLAB_OPENSSL` override, then the CryptoLab-managed user-local
backend, then an administrator-managed `/opt/openssl-3.5` backend, and finally `openssl` on
`PATH`. This requirement does not change the runtime behavior of the pre-existing
CryptoLab 1.0.0 capabilities.

## Validation

Generic unit, rendering, CLI, and mocked-backend tests remain portable across the normal
Python matrix. A dedicated release-gated CI job runs on an environment with OpenSSL 3.5+
and performs real ML-KEM, ML-DSA, and SLH-DSA workflows.

SageMath remains optional and isolated. It is not a backend for standardized PQC operations.
