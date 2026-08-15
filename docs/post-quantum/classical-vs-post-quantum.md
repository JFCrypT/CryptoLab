# Classical versus post-quantum public-key cryptography

CryptoLab 1.1.0 keeps all existing classical public-key material and adds standardized PQC
beside it. Nothing in the 1.0.0 implementation is replaced.

## Key establishment

| Construction | Operation model | Main mathematical family | Post-quantum design | CryptoLab category |
|---|---|---|---|---|
| finite-field Diffie-Hellman | key agreement | finite-field discrete logarithm | no | educational |
| X25519 | key agreement | elliptic-curve discrete logarithm | no | library-backed |
| ML-KEM | key encapsulation | module lattices / Module-LWE | yes | library-backed |

A key agreement and a KEM solve related protocol problems but do not have identical APIs.
With X25519 both parties contribute key-agreement material. With ML-KEM a recipient owns a
KEM key pair and the sender encapsulates to that public key.

## Digital signatures

| Construction | Mathematical family | Post-quantum design | Characteristic tradeoff | CryptoLab category |
|---|---|---|---|---|
| RSA-PSS | integer factorization | no | mature, comparatively large classical keys | library-backed |
| Ed25519 | elliptic curves | no | compact mature keys and signatures | library-backed |
| ML-DSA | module lattices | yes | larger keys/signatures than Ed25519 | library-backed |
| SLH-DSA | hash-based | yes | very large signatures, diverse assumptions | library-backed |

## Migration is not simple substitution

The presence of a standardized PQC primitive does not mean that a protocol can safely swap
one algorithm identifier for another. Protocol composition, authentication, certificate or
identity binding, algorithm negotiation, downgrade protection, key derivation, transcript
binding, serialization, and operational deployment remain system-level concerns.

CryptoLab 1.1.0 deliberately stops below TLS, X.509, PKI, hybrid protocol design, and network
deployment. The comparison commands are educational summaries, not protocol migration
tools.

## CLI comparisons

```bash
uv run cryptolab --explain post-quantum compare-key-establishment
uv run cryptolab --explain post-quantum compare-signatures
uv run cryptolab --explain post-quantum overview
```
