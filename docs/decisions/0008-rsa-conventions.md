# ADR 0008: RSA conventions

- **Status:** accepted
- **Decision date:** 2026-08-01

## Decision

CryptoLab separates RSA into one educational module and one library-backed applied module
under `cryptolab public-key rsa`.

Educational RSA:

- uses two distinct primes of at most 20 bits each;
- reports both Euler's totient and Carmichael's function;
- defines `d` as the canonical inverse of `e` modulo `phi(n)` to match the teaching
  convention;
- additionally reports `d_lambda`, the canonical inverse modulo `lambda(n)`;
- exposes CRT parameters and cross-checks direct and CRT decryption;
- accepts integer representatives only;
- uses unsigned big-endian integer/byte conversion;
- labels every operation as insecure textbook RSA.

Applied RSA:

- uses `cryptography`;
- allows 2048-, 3072-, and 4096-bit keys with exponent 65537;
- serializes unencrypted PKCS#8 private PEM and SubjectPublicKeyInfo public PEM;
- fixes RSA-OAEP to SHA-256, MGF1-SHA-256, and an empty label;
- fixes RSA-PSS to SHA-256, MGF1-SHA-256, and a 32-byte salt;
- validates OAEP message bounds and modulus-sized ciphertext/signature inputs;
- returns a generic failure for OAEP decoding or PSS verification;
- does not implement PKCS#1 v1.5 encryption or signing.

## Rationale

The split preserves transparent mathematics without suggesting that textbook RSA is secure.
Fixed applied parameters keep the CLI inspectable and avoid turning CryptoLab into a general
RSA configuration surface. The selected schemes correspond to the approved project scope
and the modern PKCS #1 constructions in RFC 8017.

## Rejected alternatives

- Implementing OAEP or PSS manually was rejected because modern primitives must remain
  library-backed.
- Adding PKCS#1 v1.5 encryption or signatures was rejected because they are outside the
  approved initial scope.
- Adding encrypted private-key password handling was rejected because CryptoLab is not a
  key-management product.
- Adding a complete hybrid-encryption container was rejected as protocol and file-format
  scope growth.

## Consequences

RSA examples remain local and file-based. The generated private PEM requires careful local
handling despite owner-only file permissions. RSA-OAEP is limited to short messages, while
bulk encryption remains the responsibility of an AEAD construction in an external protocol.
