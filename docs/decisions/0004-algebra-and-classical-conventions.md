# ADR 0004: Algebra and classical-cipher conventions

- **Status:** Accepted
- **Scope:** Version 1.0.0

## Decision

CryptoLab implements only algebraic computations directly relevant to cryptography:
properties of `Z_n`, the additive group, the multiplicative unit group, element order,
generated subgroups, generators, and primitive roots modulo a prime.

Enumeration is limited to moduli at most `4096`.

Classical ciphers use explicit ordered Unicode alphabets. Symbols are unique, consist of one
code point, and are never normalized or case-converted silently. The default alphabet is
`latin-upper`; `spanish-upper` is also packaged.

Unknown message symbols use an explicit `preserve` or `reject` policy. Vigenère advances
the key only for transformed symbols.

Polybius ciphertext uses space-separated two-digit coordinates and `u+HEX` tokens for
preserved symbols.

## Rationale

The selected algebraic interface demonstrates the structures used by modular cryptography
without creating a general abstract-algebra framework. Explicit alphabet and Polybius
conventions preserve reproducibility and eliminate ambiguous parsing.

## Rejected alternatives

- A generic user-defined binary-operation algebra engine was rejected as unnecessary scope.
- Silent uppercase conversion and accent removal were rejected because they alter data.
- Treating every Polybius whitespace separator as a plaintext space was rejected because it
  conflicts with coordinate-token separation.
- Automatic language ranking of Caesar candidates was deferred to the approved controlled
  laboratory.

## Consequences

Custom alphabet files are validated strictly. Multiplicative order rejects non-units. A
non-cyclic unit group returns an empty generator set as a valid mathematical result.
