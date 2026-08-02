# Educational finite-field Diffie-Hellman

CryptoLab implements finite-field Diffie-Hellman only as a transparent educational module
over deliberately small prime fields. It is key agreement, not encryption, and it does not
authenticate participants by itself.

## Public parameters

The module uses the multiplicative group `Z_p^*`, where:

- `p` is a small prime;
- `g` is a generator of `Z_p^*`;
- the group order is `p - 1`.

For every prime factor `q` of `p - 1`, a generator candidate must satisfy:

```text
g^((p - 1) / q) mod p != 1
```

CryptoLab also computes the complete element order of `g`. A valid generator has order
`p - 1`.

```bash
uv run cryptolab --explain public-key dh group 17 3
```

## Exchange

Alice chooses a private exponent `a` and Bob chooses `b`:

```text
A = g^a mod p
B = g^b mod p
s_A = B^a mod p
s_B = A^b mod p
```

Correctness gives `s_A = s_B = g^(ab) mod p`.

The course example reproduced by CryptoLab is:

```text
p = 17
g = 3
a = 13
b = 11
A = 12
B = 7
s = 6
```

```bash
uv run cryptolab --explain public-key dh exchange 17 3 13 11
```

## HKDF-SHA-256 connection

The raw group element is not treated directly as an application session key. CryptoLab:

1. encodes the shared secret as fixed-width unsigned big-endian bytes;
2. supplies those bytes as HKDF input keying material;
3. derives a session key with HKDF-SHA-256.

The default context is `CryptoLab finite-field Diffie-Hellman`, the default output length is
32 bytes, and an optional explicit hexadecimal salt may be provided.

```bash
uv run cryptolab --explain public-key dh exchange 23 5 6 15 \
  --salt-hex 00010203 \
  --info-text "teaching session" \
  --length 32
```

## Security interpretation

The relevant mathematical assumption is the difficulty of recovering a private exponent
from a public value such as `A = g^a mod p`, which is the discrete logarithm problem in the
selected group.

CryptoLab uses tiny inspectable parameters. They are intentionally insecure and must not be
presented as practical finite-field Diffie-Hellman parameters.

Unauthenticated Diffie-Hellman does not establish who is on the other side. An active
attacker can replace the exchanged public values and establish one key with Alice and a
different key with Bob. The controlled laboratory demonstrates that failure locally.

## Boundaries

The module does not provide:

- network transport;
- standardized large finite-field groups;
- certificates or PKI;
- participant authentication;
- a discrete-logarithm solver;
- production key management;
- a complete protocol implementation.
