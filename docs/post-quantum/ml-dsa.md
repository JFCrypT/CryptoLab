# ML-DSA — FIPS 204

ML-DSA is the Module-Lattice-Based Digital Signature Algorithm standardized in NIST
FIPS 204. CryptoLab exposes the three standardized parameter sets through OpenSSL 3.5+ EVP.

## Parameter sets

| Parameter set | NIST category | Raw public key | Raw private key | Signature |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 2 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | 3 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | 5 | 2592 B | 4896 B | 4627 B |

Serialized PEM sizes differ from the raw standardized key sizes.

## Signing model

CryptoLab exposes pure ML-DSA signing and verification. An optional context string can bind
the signature to an application context. The context is limited to 255 bytes.

OpenSSL's normal ML-DSA signing path is allowed to use randomized/hedged signing behavior.
CryptoLab does not expose test-only deterministic randomness controls as a normal user option.

## Commands

```bash
uv run cryptolab post-quantum ml-dsa parameters
uv run cryptolab post-quantum ml-dsa generate ML-DSA-65 \
  --private-key-out private.pem --public-key-out public.pem
uv run cryptolab post-quantum ml-dsa sign ML-DSA-65 \
  --private-key-file private.pem --message-text "CryptoLab" \
  --context-text "demo" --signature-out signature.bin
uv run cryptolab post-quantum ml-dsa verify ML-DSA-65 \
  --public-key-file public.pem --message-text "CryptoLab" \
  --context-text "demo" --signature-file signature.bin
```

Message input follows the same explicit text/hex/file-source convention used elsewhere in
CryptoLab. Verification failure returns a non-zero verification status through the CLI.

## What verification means

A valid signature demonstrates possession of the signing private key for the verified
message and context. It does not by itself establish the real-world identity of the signer,
certificate validity, authorization, timestamping, or non-repudiation policy.
