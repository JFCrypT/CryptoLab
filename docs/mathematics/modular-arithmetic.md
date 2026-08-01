# Modular arithmetic

CryptoLab uses moduli `n >= 2` and canonical representatives in:

\[
\{0,1,\ldots,n-1\}.
\]

## Basic operations

The module provides normalization, addition, subtraction, multiplication, and fast modular
exponentiation. Exponentiation uses right-to-left square-and-multiply and exposes its
intermediate states through `--explain`.

```bash
uv run cryptolab modular normalize -9 15
uv run cryptolab --explain modular power 14 15 29
```

## Units and inverses

A residue class is a multiplicative unit exactly when:

\[
\gcd(a,n)=1.
\]

CryptoLab obtains inverses from a Bézout identity and returns the canonical inverse. The
absence of an inverse is a valid mathematical result rather than an internal error.

```bash
uv run cryptolab --explain modular inverse 13 200
uv run cryptolab modular units 15
```

## Non-zero zero divisors

CryptoLab excludes the zero class from its zero-divisor listing. For `1 <= a < n`, a
residue is listed as a non-zero zero divisor when:

\[
\gcd(a,n)>1.
\]

Enumeration is limited to moduli at most 4096.

## Linear congruences

For:

\[
ax\equiv b\pmod n,
\]

let `d = gcd(a, n)`. Solutions exist if and only if `d` divides `b`. When solutions exist,
CryptoLab returns exactly `d` incongruent canonical representatives modulo `n`.

```bash
uv run cryptolab --explain modular solve-linear 15 30 55
```

## Generalized Chinese Remainder Theorem

The CRT implementation accepts systems whose moduli are not necessarily pairwise
coprime. Two congruences:

\[
x\equiv a_1\pmod{n_1},
\qquad
x\equiv a_2\pmod{n_2}
\]

are compatible exactly when:

\[
a_1\equiv a_2\pmod{\gcd(n_1,n_2)}.
\]

A compatible system is returned as one canonical congruence modulo the least common
multiple of all moduli.

```bash
uv run cryptolab --explain modular crt \
  --congruence 5:7 \
  --congruence 0:6 \
  --congruence=-1:5
```

The example yields:

\[
x\equiv54\pmod{210}.
\]
