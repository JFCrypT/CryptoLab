# ADR 0007: Hashing, HMAC, and HKDF conventions

- **Status:** accepted
- **Decision date:** 2026-08-01

## Decision

CryptoLab version 1.0.0 includes exactly these algorithms in this topic:

- SHA-256;
- SHA3-256;
- HMAC-SHA-256;
- HKDF-SHA-256.

SHA-256 and SHA3-256 use Python's `hashlib` implementations. HMAC-SHA-256 uses Python's
`hmac` implementation and full 256-bit tags. HKDF-SHA-256 exposes both RFC 5869 stages:

1. `Extract`, implemented as HMAC-SHA-256 to produce the pseudorandom key (PRK);
2. `Expand`, delegated to `cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand` to produce
   output keying material (OKM).

The complete `cryptography` HKDF implementation independently cross-checks each combined
extract-and-expand result.

Hash input supports exactly one explicit source:

- strict UTF-8 text;
- canonical hexadecimal bytes;
- a file.

File hashing is incremental in 64 KiB chunks. Digest and HMAC verification accept only
full 32-byte values and use `hmac.compare_digest`. A mismatch exits with code `4`.

The avalanche command requires two distinct, equal-length inputs. It reports:

- changed input bits;
- both 256-bit digests;
- digest XOR;
- changed digest bits;
- the percentage of changed digest bits;
- a byte-level difference table.

One avalanche observation is explicitly presented as an illustration, not as a statistical
proof or a security validation.

HKDF accepts an omitted salt. In that case, the effective extract salt is 32 zero bytes, as
specified for SHA-256 by RFC 5869. `info` defaults to an empty byte string. Output length is
restricted to `1..8160` bytes, the RFC limit of `255 * HashLen` for SHA-256.

## Rationale

This design keeps modern primitives library-backed while exposing the internal boundaries that
are pedagogically important. It avoids implementing SHA-2, Keccak, or HMAC internals from
scratch. The staged HKDF result makes PRK, context information, and OKM inspectable and can be
reused by later Diffie-Hellman and X25519 examples.

Full-length digests and tags avoid introducing truncation policy into the initial scope.
Incremental file hashing demonstrates practical API use without loading an arbitrary file into
memory. CryptoLab rejects empty HMAC keys and empty HKDF input keying material as an explicit
input policy for its didactic interface.

## Rejected alternatives

- Implementing SHA-256 or Keccak manually was rejected because it would duplicate established
  primitives without improving the approved scope.
- Adding SHAKE, BLAKE, MD5, SHA-1, CMAC, password hashing, or a general hash catalog was
  rejected because those items are outside version 1.0.0.
- Treating a plain digest as message authentication was rejected as cryptographically
  incorrect.
- Using HKDF as a password-hashing function was rejected because HKDF is not designed for
  password storage.
- Returning success for a failed digest or HMAC verification was rejected because a scriptable
  CLI needs an unambiguous nonzero status.

## Consequences

- Later finite-field Diffie-Hellman and X25519 modules MUST call the same HKDF-SHA-256 API.
- Later comparisons MUST distinguish HMAC from digital signatures.
- Version 1.0.0 does not provide password hashing or arbitrary tag truncation.
- Published vectors validate reproducibility but do not constitute certification, formal
  verification, or independent audit.
