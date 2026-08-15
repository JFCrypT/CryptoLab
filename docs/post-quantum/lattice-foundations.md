# Lattice and polynomial foundations

ML-KEM and ML-DSA are module-lattice constructions. CryptoLab introduces only the
mathematical ideas needed to interpret their high-level structure; it does not reproduce the
standardized algorithms or provide a lattice-attack toolkit.

## Polynomial rings

A useful model is a quotient ring of polynomials over integers modulo `q`. In a simple
educational negacyclic example,

\[
R_q = \mathbb{Z}_q[x]/(x^n+1).
\]

The relation `x^n = -1` means a product term whose degree reaches `n` wraps around with a
negative sign. CryptoLab exposes this calculation only for small bounded vectors:

```bash
uv run cryptolab --explain post-quantum foundations ring-multiply \
  17 "1,2" "3,4"
```

For `(1 + 2x)(3 + 4x)` in `Z_17[x]/(x^2+1)`, ordinary multiplication gives
`3 + 10x + 8x^2`. Since `x^2 = -1`, the result is `-5 + 10x`, or the canonical coefficient
vector `[12, 10]` modulo 17.

## Learning With Errors

The pedagogical relation

\[
b = As + e \pmod q
\]

captures the central idea that a linear modular relation is perturbed by a small error
vector. CryptoLab can compute tiny explicit examples so that the role of `A`, `s`, `e`, and
modular reduction is visible:

```bash
uv run cryptolab --explain post-quantum foundations lwe-example \
  17 --row "1,2" --row "3,4" --secret "5,6" --error "1,-1"
```

This is **not** a secure LWE sampler. It does not reproduce the parameter distributions,
module structure, transforms, compression, rejection sampling, or other details of FIPS 203
or FIPS 204.

## Module-LWE and Module-SIS

At a conceptual level:

- **Module-LWE** extends LWE-style noisy linear relations to module elements over a
  polynomial ring and is central to the security foundation of ML-KEM;
- **Module-SIS** is a short-integer-solution problem over modules and contributes to the
  security foundation of ML-DSA.

The standardized schemes must be studied from FIPS 203 and FIPS 204 for exact algorithms,
parameters, encodings, rejection conditions, and security requirements.

## Why CryptoLab stops here

Implementing an educational toy relation is useful because every arithmetic operation can
be inspected. Reimplementing a standardized PQC primitive would create a second,
non-production implementation with substantial risk and little benefit for the project's
bounded scope. The actual ML-KEM and ML-DSA commands therefore use OpenSSL 3.5+ EVP.
