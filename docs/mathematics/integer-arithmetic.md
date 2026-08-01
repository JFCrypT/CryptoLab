# Integer arithmetic

The integer arithmetic module is an educational implementation that exposes the elementary
number-theory operations used throughout CryptoLab.

## Natural numbers

CryptoLab uses:

\[
\mathbb N=\{1,2,3,\ldots\}
\]

and:

\[
\mathbb N_0=\{0,1,2,3,\ldots\}.
\]

## Euclidean division

For integers \(a\) and \(b\ne 0\), CryptoLab returns the unique quotient \(q\) and
remainder \(r\) satisfying:

\[
a=bq+r,
\]

\[
0\le r<|b|.
\]

This convention also applies when the divisor is negative and intentionally differs from
Python's native floor-division remainder convention in that case.

## Divisibility

CryptoLab adopts:

\[
a\mid b\iff a\ne 0\land\exists k\in\mathbb Z: b=ak.
\]

A zero divisor argument is rejected. Divisors of zero are not enumerated because the set is
infinite.

## Greatest common divisor

The gcd is non-negative:

\[
\gcd(a,b)\ge0,
\]

with:

\[
\gcd(0,0)=0.
\]

The extended algorithm returns coefficients \(x\) and \(y\) such that:

\[
ax+by=\gcd(a,b).
\]

## Primality and factorization limits

Primality testing and factorization use deterministic educational trial division and accept
integers up to \(2^{40}\). These functions are not intended for cryptographic RSA moduli.
