# Release traceability

This page maps the principal version 1.0.0 requirements to implementation, documentation, and
validation evidence.

| Requirement | Implementation | Documentation | Validation evidence |
|---|---|---|---|
| Integer and number-theory foundations | `src/cryptolab/mathematics/integers.py` | integer arithmetic page | unit, property, CLI, and integration tests |
| Linear Diophantine equations | `src/cryptolab/mathematics/diophantine.py` | Diophantine page | solvable, unsolvable, boundary, and property tests |
| Modular arithmetic and CRT | `src/cryptolab/mathematics/modular.py` | modular arithmetic page | identities, generalized CRT, invalid-input, and property tests |
| Algebraic structures | `src/cryptolab/mathematics/algebra.py` | algebraic structures page | group-order, generator, and structure tests |
| Classical cryptography | `src/cryptolab/classical/` | classical pages | round trips, known examples, and controlled Caesar analysis |
| XOR, Vernam, OTP, and LFSR | `src/cryptolab/symmetric/`, `src/cryptolab/sequences/` | symmetric and sequence pages | identity, period, sequence, and key-reuse tests |
| Modern symmetric cryptography | `src/cryptolab/symmetric/modern.py` | AES and ChaCha pages | NIST/RFC vectors, round trips, authentication failures |
| Hash, HMAC, and HKDF | `src/cryptolab/hashing/` | hashing pages | published vectors and verification failures |
| RSA | `src/cryptolab/public_key/rsa_*` | RSA pages | educational identities, OAEP/PSS round trips and failures |
| Finite-field DH | `src/cryptolab/public_key/diffie_hellman.py` | DH page | group checks, shared-secret equality, MITM laboratory |
| Educational ECC | `src/cryptolab/public_key/elliptic_curve.py` | educational ECC page | point arithmetic, order, subgroup, and boundary tests |
| X25519 and Ed25519 | `src/cryptolab/public_key/modern_curves.py` | modern curve pages | RFC 7748 and RFC 8032 vectors, invalid verification tests |
| Exactly four controlled laboratories | `src/cryptolab/labs/` | laboratory pages | registry and release-readiness checks |
| Mandatory release readiness | `scripts/check_release.py` | release acceptance and process | metadata, scope, archives, installation, and CI checks |
| Optional direct SageMath comparison | `scripts/cross_validate.py`, `sagemath/compute_reference.py` | SageMath cross-validation page | dynamic same-input comparison when explicitly executed |

The release checker validates metadata, scope guardrails, required documents, and distribution
contents. Optional SageMath results are supplementary evidence only.
