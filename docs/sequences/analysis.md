# Elementary binary-sequence analysis

CryptoLab provides lightweight educational measurements for finite binary sequences.
These measurements are not a cryptographic randomness test suite.

## Period

The fundamental period is the smallest positive divisor `T` of the sequence length for which
the supplied sequence consists of repetitions of its first `T` bits.

## Balance

CryptoLab reports the number of zeros, the number of ones, and their absolute difference. A
finite sequence is labelled balanced when the counts differ by at most one.

## Runs

Runs are counted cyclically. If the first and final symbols are equal, their runs are merged
across the period boundary. Counts are grouped by bit value and run length.

## Periodic autocorrelation

CryptoLab uses bipolar periodic autocorrelation:

\[
C(\tau)=\sum_{i=0}^{N-1}
(-1)^{s_i\oplus s_{(i+\tau)\bmod N}}.
\]

The normalized value is `C(tau) / N`. Equivalently, the unnormalized value is the number of
coincidences minus the number of differences between the original sequence and its periodic
shift.

```bash
uv run cryptolab --explain sequence analyze 1010011 --max-lag 6
```

For this maximum-length degree-3 example, `C(0) = 7` and every non-zero lag has value `-1`.

## Limits and interpretation

- sequence length: at most 100,000 bits;
- displayed autocorrelation lags: at most 4,096;
- period, balance, runs, and autocorrelation are necessary descriptive properties only;
- favorable values do not establish unpredictability or cryptographic security.
