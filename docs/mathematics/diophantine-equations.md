# Linear Diophantine equations

CryptoLab solves equations of the form:

\[
ax+by=c,
\]

where all coefficients and unknowns are integers.

## Solvability criterion

Let:

\[
d=\gcd(a,b).
\]

When at least one of `a` or `b` is non-zero, the equation has an integer solution if and
only if:

\[
d\mid c.
\]

If `a = b = 0`, then every integer pair solves the equation when `c = 0`; otherwise no
integer pair solves it.

## General solution

If `(x0, y0)` is one particular solution, every solution is:

\[
x=x_0+\frac{b}{d}t,
\]

\[
y=y_0-\frac{a}{d}t,
\]

with:

\[
t\in\mathbb Z.
\]

CryptoLab derives the particular solution from an extended Euclidean algorithm result and
verifies it before returning the solution family.

## Equivalent reduction

The displayed reduced equation is obtained by dividing `a`, `b`, and `c` by their common
gcd. The sign is then normalized so that the first non-zero coefficient is positive. This
reduction preserves the complete integer solution set.

## Commands

Solve an equation:

```bash
uv run cryptolab --explain diophantine solve 33 17 1
```

Verify a candidate pair:

```bash
uv run cryptolab diophantine verify 2 -5 1 3 1
```

A statement that an equation has no solution is a valid mathematical result and returns
exit code zero.
