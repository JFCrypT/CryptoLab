# Educational textbook RSA

CryptoLab implements textbook RSA only to expose the arithmetic. It is deterministic,
has no secure message encoding, and **must not protect real data**.

## Key construction

For two distinct small primes `p` and `q`:

\[
n=pq,
\qquad
\varphi(n)=(p-1)(q-1),
\qquad
\lambda(n)=\operatorname{lcm}(p-1,q-1).
\]

The educational interface follows the common Euler-totient convention:

\[
1<e<\varphi(n),
\qquad
\gcd(e,\varphi(n))=1,
\qquad
d_{\varphi}=e^{-1}\pmod{\varphi(n)}.
\]

It also reports the minimal inverse

\[
d_{\lambda}=e^{-1}\pmod{\lambda(n)}.
\]

The two private exponents are congruent modulo `lambda(n)` and therefore induce the same
RSA permutation. CryptoLab labels the Euler-totient inverse as `d` because it matches the
teaching convention, while retaining `d_lambda` explicitly.

## CRT parameters

The module derives:

\[
d_P=d\bmod(p-1),
\qquad
d_Q=d\bmod(q-1),
\qquad q_{\mathrm{inv}}=q^{-1}\bmod p.
\]

Decryption is cross-checked by both direct exponentiation and CRT reconstruction:

\[
m_1=c^{d_P}\bmod p,
\qquad
m_2=c^{d_Q}\bmod q,
\]

\[
h=q_{\mathrm{inv}}(m_1-m_2)\bmod p,
\qquad
m=m_2+hq.
\]

## Deliberate limits

- `p` and `q` are limited to 20 bits each.
- generated primes are deliberately small and inspectable;
- input representatives must satisfy `0 <= m < n` or `0 <= c < n`;
- the default generated public exponent is `65537`;
- no padding, randomized encoding, chunking, or production key storage is provided.

These limits keep the module didactic and prevent it from becoming a practical RSA
implementation.

## Classic example

```bash
uv run cryptolab --explain public-key rsa educational inspect 61 53 17
uv run cryptolab public-key rsa educational encrypt 65 --p 61 --q 53 --e 17
uv run cryptolab --explain public-key rsa educational decrypt 2790 --p 61 --q 53 --e 17
```

The example yields:

```text
n = 3233
phi(n) = 3120
lambda(n) = 780
d = 2753
d_lambda = 413
65^17 mod 3233 = 2790
2790^2753 mod 3233 = 65
```

## Generated teaching keys

```bash
uv run cryptolab --explain public-key rsa educational generate \
  --prime-bits 12 \
  --e 65537
```

The output is intentionally non-deterministic because prime candidates come from the
operating-system-backed `secrets` source. Mathematical identities and bounds remain fully
testable.

## Integer and byte conversion

RSA standards convert octet strings and integers. CryptoLab uses unsigned, big-endian
conversion with minimal length unless a length is explicitly requested. Zero is represented
as one zero byte.

```bash
uv run cryptolab public-key rsa convert integer-to-bytes 3233
uv run cryptolab public-key rsa convert bytes-to-integer 0ca1
uv run cryptolab --explain public-key rsa convert integer-to-bytes 1 --length 4
```

## Security boundary

Textbook RSA exposes the modular equations but omits the secure encodings required by
applied RSA. Equal messages always produce equal ciphertexts, algebraic relationships are
preserved, and arbitrary byte strings are not safely represented. Use RSA-OAEP for the
approved applied encryption demonstration and RSA-PSS for signatures.
