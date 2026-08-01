# Controlled laboratory: Vernam key reuse

## Identifier

`vernam-key-reuse`

## Purpose

This laboratory encrypts two equal-length local messages with the same deliberately reused
key and demonstrates:

\[
C_1\oplus C_2
=(M_1\oplus K)\oplus(M_2\oplus K)
=M_1\oplus M_2.
\]

```bash
uv run cryptolab --explain lab vernam-key-reuse \
  --message-one-hex beca \
  --message-two-hex bcee \
  --key-hex fe12
```

## Demonstrated failure

The XOR of the ciphertexts exposes the XOR of the corresponding plaintexts. This does not
mean that CryptoLab automatically recovers both messages, but it removes the key stream from
the relation and exposes exploitable plaintext structure.

## Violated assumption

The key stream was not used exactly once.

## Mitigation

Never reuse One-Time Pad material. For modern stream ciphers and AEAD constructions, never
reuse a nonce with the same key when the construction forbids reuse.

The laboratory operates only on deliberately vulnerable local examples.
