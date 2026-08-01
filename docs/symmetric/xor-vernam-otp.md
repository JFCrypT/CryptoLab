# XOR, Vernam, and the One-Time Pad

## Implementation category

The XOR and Vernam modules are **educational implementations**. They expose every input,
output, and intermediate byte. They are not a modern authenticated-encryption interface.

## XOR

For bits `x` and `y`, XOR is addition modulo 2:

\[
x \oplus y = x + y \pmod 2.
\]

| x | y | x XOR y |
|---:|---:|---:|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

XOR is self-inverse:

\[
(m \oplus k) \oplus k = m.
\]

CryptoLab supports equal-length bit strings and equal-length byte strings. Byte inputs are
selected explicitly as UTF-8 text, canonical hexadecimal, or a file. CryptoLab does not
autodetect encodings.

```bash
uv run cryptolab symmetric xor truth-table
uv run cryptolab symmetric xor bits 1011 1111
uv run cryptolab --explain symmetric xor bytes \
  --left-hex beca \
  --right-hex fe12
```

## Vernam construction

For an equal-length binary message and key stream:

\[
c_i = m_i \oplus k_i,
\qquad
m_i = c_i \oplus k_i.
\]

CryptoLab applies this operation byte by byte while showing the equivalent bit strings. The
teaching example below produces `40d8`:

```bash
uv run cryptolab --explain symmetric vernam encrypt \
  --message-hex beca \
  --key-hex fe12

uv run cryptolab --explain symmetric vernam decrypt \
  --ciphertext-hex 40d8 \
  --key-hex fe12
```

The software verifies only input format and equal length. It does not claim that the key is
random, secret, or used once.

## Strict One-Time Pad requirements

A Vernam operation is a true One-Time Pad only when every condition below holds:

1. the key is uniformly random;
2. the key is at least as long as the message;
3. the key is used exactly once;
4. the key is distributed securely;
5. the key is stored securely;
6. the key is destroyed securely after use.

```bash
uv run cryptolab --explain symmetric otp requirements
```

CryptoLab cannot prove that a supplied key satisfies randomness, secrecy, distribution,
storage, destruction, or one-time-use requirements. The One-Time Pad is therefore explained
as an information-theoretic construction, not presented as a general practical solution.
