# Modern curve comparisons

CryptoLab keeps educational elliptic-curve arithmetic separate from modern library-backed
operations.

## Educational ECC versus X25519

The educational module exposes affine formulas, point enumeration, addition, doubling,
scalar multiplication, and subgroup order over tiny prime fields. X25519 is delegated to
`cryptography` and exposes only the correct high-level key-agreement operation. The tiny
teaching curves are not substitutes for X25519.

## Finite-field Diffie-Hellman versus X25519

Both constructions establish a shared secret and both require authentication from a larger
protocol. CryptoLab applies HKDF-SHA-256 after each raw shared-secret computation. The
finite-field module uses inspectable toy parameters; X25519 uses a standardized modern
curve and fixed-size byte encodings through the library API.

## RSA-PSS versus Ed25519

Both are public-key digital signatures. The CryptoLab RSA-PSS profile uses SHA-256,
MGF1-SHA-256, a 32-byte random salt, and modulus-sized signatures. Ed25519 uses 32-byte raw
public keys and fixed 64-byte deterministic signatures. Selection depends on protocol,
interoperability, key infrastructure, implementation environment, and policy.

## HMAC versus signatures

HMAC-SHA-256 is a symmetric MAC. RSA-PSS and Ed25519 are digital signatures. The shared-key
nature of HMAC changes the trust model and prevents it from serving as a public-verification
signature mechanism.
