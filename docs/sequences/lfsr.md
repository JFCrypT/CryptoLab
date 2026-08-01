# Linear Feedback Shift Registers

## Security status

The LFSR implementation is **educational-only**. An LFSR by itself is linear, predictable,
and unsuitable as a cryptographically secure pseudorandom generator.

## Fixed CryptoLab convention

CryptoLab uses one explicit convention and never mixes it silently.

For the binary connection polynomial

\[
C(x)=x^m+c_{m-1}x^{m-1}+\cdots+c_1x+c_0,
\]

CryptoLab requires `c0 = 1` and represents the state as

\[
S_t=[s_{m-1},s_{m-2},\ldots,s_1,s_0].
\]

The rules are:

- Fibonacci LFSR;
- right shift;
- output bit: `s0`, the rightmost stage;
- feedback bit:

\[
f=\bigoplus_{i:c_i=1}s_i;
\]

- transition:

\[
[s_{m-1},\ldots,s_1,s_0]
\longrightarrow
[f,s_{m-1},\ldots,s_1].
\]

The leading coefficient of `x^m` defines the degree and is not a feedback tap. Polynomial
input uses canonical `x` notation. `D` notation may appear in references but is rejected as
CLI input to prevent convention ambiguity.

## Example

For

\[
C(x)=x^3+x^2+1,
\qquad
S_0=[1,0,1],
\]

the feedback is `s2 XOR s0`, the period is 7, and the sequence begins:

```text
101001110100111...
```

```bash
uv run cryptolab --explain sequence lfsr diagram "x^3+x^2+1"
uv run cryptolab --explain sequence lfsr period "x^3+x^2+1" 101
uv run cryptolab --explain sequence lfsr generate "x^3+x^2+1" 101 21
```

## Period and cycle detection

CryptoLab uses deterministic cycle detection from the supplied seed. It reports:

- preperiod;
- period;
- whether the cycle returns to the seed;
- the maximum possible non-zero period `2^m - 1`;
- whether the observed sequence has maximum length;
- whether the seed is the all-zero fixed point.

A maximum period is only one desirable statistical property. It does not make a standalone
LFSR cryptographically secure.

## Resource limits

- degree: 2 through 24;
- generated sequence: at most 1,000,000 bits;
- state trace: at most 100,000 rows.
