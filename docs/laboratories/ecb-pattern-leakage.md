# Controlled laboratory: ECB pattern leakage

## Purpose

This laboratory demonstrates that AES-ECB deterministically maps equal plaintext blocks to
equal ciphertext blocks under one key.

## Scope

The command operates only on deliberately supplied local hexadecimal data. It requires at
least two complete AES blocks and disables padding so block boundaries remain explicit.

```bash
cryptolab --explain lab ecb-pattern-leakage \
  --key-hex 000102030405060708090a0b0c0d0e0f \
  --plaintext-hex \
00112233445566778899aabbccddeeff0000000000000000000000000000000000112233445566778899aabbccddeeff
```

The table displays every plaintext block and its ciphertext block. The first and third
plaintext blocks are equal, so the corresponding ciphertext blocks are also equal.

## Violated assumption

ECB does not hide equality patterns between blocks. Adding padding does not change that
property for repeated aligned blocks.

## Security effect

An observer can infer repeated structure, boundaries, and relationships even without knowing
the key or plaintext values.

## Mitigation

Use a construction appropriate to the data and threat model. General message encryption
normally requires authenticated encryption such as AES-GCM or ChaCha20-Poly1305. Storage
encryption has different requirements and may use XTS, but XTS still does not authenticate
modifications.

This is one of exactly four approved CryptoLab 1.0.0 laboratories. It does not target external
systems.
