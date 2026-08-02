# ADR 0010: Elliptic curves, X25519, and Ed25519 conventions

## Status

Accepted for the version 1.0.0 implementation.

## Decision

Educational elliptic-curve arithmetic MUST use short-Weierstrass curves
`y^2 = x^3 + ax + b mod p` over odd prime fields with `5 <= p <= 257`.

Finite points MUST use canonical `x:y` CLI tokens. The point at infinity MUST use the
literal token `infinity`. Coordinates MUST be normalized modulo `p`, and finite points MUST
be validated before every public operation.

A curve MUST be rejected when `4a^3 + 27b^2 = 0 mod p`.

Point multiplication MUST use a transparent right-to-left double-and-add trace. Educational
parameters MUST NOT be presented as secure.

X25519 and Ed25519 MUST be provided only through the established `cryptography` library.
They MUST NOT be manually reimplemented.

X25519 raw shared secrets MUST be checked for equality and for the all-zero value, then
passed to HKDF-SHA-256. X25519 MUST be documented as unauthenticated key agreement.

Ed25519 signatures MUST use pure Ed25519. Raw private and public keys MUST contain exactly
32 bytes and signatures MUST contain exactly 64 bytes. Invalid verification MUST return the
project verification-failure exit code.

Generated X25519 and Ed25519 private keys MUST use unencrypted PKCS#8 PEM with mode `0600`.
Public keys MUST use SubjectPublicKeyInfo PEM with mode `0644`.

## Rationale

This split preserves transparent mathematical teaching while avoiding unsafe
reimplementation of modern primitives. Fixed representations make CLI, tests, JSON, and
published vectors reproducible.

## Rejected alternatives

- Manual X25519 or Ed25519 implementations were rejected as unnecessary and unsafe.
- ECDSA and P-256 were rejected because they are outside the approved initial scope.
- Binary curves, pairing-based curves, advanced projective coordinates, and curve catalogs
  were rejected as scope growth.
- Treating a raw X25519 shared secret as a session key was rejected in favor of HKDF.

## Consequences

The educational module remains intentionally small and non-production. Modern curve
operations depend on `cryptography`. Key generation writes local unencrypted private keys,
so users must protect those files and understand that CryptoLab is not a key-management
system.
