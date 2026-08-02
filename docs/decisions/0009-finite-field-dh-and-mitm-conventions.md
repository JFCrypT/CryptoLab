# ADR 0009: finite-field Diffie-Hellman and MITM conventions

## Status

Accepted.

## Decision

CryptoLab uses the following conventions for educational finite-field Diffie-Hellman:

- the ambient group is the full multiplicative group `Z_p^*`;
- `p` MUST be prime and MUST satisfy `5 <= p <= 4096`;
- `g` MUST be a generator of `Z_p^*` for an exchange;
- group inspection MAY report a non-generator without performing an exchange;
- generator validation MUST use both element order and the prime-factor tests of `p - 1`;
- private exponents MUST satisfy `2 <= exponent <= p - 2`;
- public values and shared secrets MUST use modular exponentiation;
- the shared group element MUST be encoded as fixed-width unsigned big-endian bytes;
- HKDF-SHA-256 MUST derive the displayed session key;
- the default HKDF output length is 32 bytes;
- the module MUST state that Diffie-Hellman is key agreement, not encryption;
- the module MUST state that unauthenticated Diffie-Hellman does not authenticate peers.

The controlled man-in-the-middle laboratory MUST:

- replace both public values locally;
- establish one shared secret with Alice and another with Bob;
- show that Mallory derives both corresponding HKDF keys;
- update the existing four-item laboratory registry from `planned` to `implemented`;
- remain the fourth and final approved cryptanalysis laboratory.

## Rationale

The full multiplicative group modulo a small prime gives an inspectable connection between
primitive roots, element orders, modular exponentiation, the discrete logarithm problem,
and the Diffie-Hellman correctness identity. The explicit KDF step connects the earlier
HKDF module to key agreement without turning CryptoLab into a network protocol or key
management system.

## Rejected alternatives

- Large standardized finite-field groups were rejected because they obscure the educational
  arithmetic and imply a production-oriented interface.
- Manual discrete-logarithm attacks were rejected because they are outside the approved
  cryptanalysis scope.
- Networked peers were rejected because CryptoLab is not a network service.
- Treating the raw shared group element as the final session key was rejected because the
  approved scope explicitly connects Diffie-Hellman examples to HKDF.

## Consequences

All parameters are intentionally small and insecure. The module is transparent and
reproducible but MUST NOT be described as a production Diffie-Hellman implementation.
