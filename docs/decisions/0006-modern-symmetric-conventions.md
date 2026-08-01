# ADR 0006: Modern symmetric cryptography conventions

## Status

Accepted for CryptoLab 1.0.0.

## Decision

Modern symmetric primitives are **library-backed** and use the `cryptography` package.
CryptoLab does not implement AES, GCM, ChaCha20, or Poly1305 from scratch.

The supported AES key sizes are:

- 16 bytes for AES-128;
- 32 bytes for AES-256;
- 32 bytes for XTS-AES-128, interpreted as two 128-bit AES keys;
- 64 bytes for XTS-AES-256, interpreted as two 256-bit AES keys.

AES always has a 128-bit block size. AES-128 and AES-256 name the key size, not the block
size. AES-192 is outside the initial scope.

The CLI accepts cryptographic keys, IVs, nonces, counters, tweaks, tags, and binary inputs as
canonical hexadecimal without a prefix, whitespace, or separators. Plaintext and associated
data may alternatively be supplied as strict UTF-8 or file bytes.

Mode parameters are fixed as follows:

| Mode | Required external value | Length | Padding |
|---|---|---:|---|
| ECB | none | — | explicit `pkcs7` or `none` |
| CBC | IV | 16 bytes | explicit `pkcs7` or `none` |
| CFB-128 | IV | 16 bytes | none |
| OFB | IV | 16 bytes | none |
| CTR | initial counter block | 16 bytes | none |
| GCM | nonce | 12 bytes | none |
| XTS | tweak | 16 bytes | none |

GCM uses a 16-byte authentication tag. ChaCha20-Poly1305 uses a 32-byte key, a 12-byte
nonce, and a 16-byte authentication tag. Authenticated decryption returns exit code `4` when
tag verification fails.

CFB is fixed to the 128-bit segment variant. CryptoLab does not expose CFB8.

XTS is restricted to storage data units. A data unit must contain at least one AES block. The
two component keys must not be identical. XTS does not authenticate data.

ECB is exposed only for educational comparison and the approved pattern-leakage laboratory.

## Rationale

The selected API demonstrates correct use of established primitives while preserving the
project boundary against becoming a cryptographic implementation suite. Fixed lengths and
explicit parameter names reduce ambiguity and make vector validation reproducible.

The project uses a compatibility import for CFB and OFB because recent `cryptography`
versions moved these legacy modes to the decrepit namespace. Their inclusion is required by
the approved didactic scope and does not imply a recommendation for new designs.

## Rejected alternatives

- Reimplementing AES, ChaCha20, Poly1305, or GCM was rejected as unnecessary and unsafe.
- Accepting AES-192 was rejected because it is outside the approved initial scope.
- Automatically generating or silently deriving IVs, nonces, counters, and tweaks was
  rejected because the CLI must expose parameter semantics explicitly.
- Combining the authentication tag with ciphertext in displayed output was rejected in
  favor of separate fields that make AEAD structure visible.
- Treating XTS as a general message mode was rejected because its purpose is storage
  encryption.

## Consequences

- `cryptography` is a required runtime dependency.
- Library-backed operations inherit the supported-platform constraints of `cryptography`
  and its OpenSSL backend.
- Passing public vectors verifies interoperability but does not constitute certification,
  formal verification, or an independent audit.
