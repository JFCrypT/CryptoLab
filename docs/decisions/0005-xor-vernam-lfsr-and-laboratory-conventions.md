# ADR 0005: XOR, Vernam, LFSR, and controlled-laboratory conventions

## Status

Accepted.

## Decision

CryptoLab implements XOR and Vernam transparently over equal-length inputs. A Vernam
operation is never labelled a One-Time Pad automatically. The OTP module exposes the six
strict project requirements and states that CryptoLab cannot verify randomness, secrecy,
distribution, storage, destruction, or prior use.

The LFSR module uses a Fibonacci register with right shift, state ordering
`[s_(m-1), ..., s_0]`, output stage `s_0`, and feedback
`XOR(c_i * s_i)` for coefficients below the leading term. Canonical polynomial input uses
`x`, requires `c0 = 1`, and has degree 2 through 24.

The binary-sequence analyzer uses cyclic runs and periodic bipolar autocorrelation. These
statistics are documented as descriptive and insufficient for cryptographic security.

The controlled-laboratory registry contains exactly four approved identifiers. This milestone
implements `caesar-brute-force` and `vernam-key-reuse`; the ECB and Diffie-Hellman
laboratories remain planned until their underlying modules exist.

## Rationale

Explicit input formats and one LFSR convention prevent silent changes in bit order, stage
order, polynomial notation, or shift direction. Reusing public cipher and XOR modules keeps
laboratories reproducible and avoids duplicate implementations.

## Consequences

- XOR inputs must have equal length.
- Byte sources are selected explicitly as text, hexadecimal, or file input.
- LFSR `D` notation is documented but rejected as canonical CLI input.
- Maximum period is not described as cryptographic security.
- No laboratory outside the four approved identifiers may be introduced silently.
