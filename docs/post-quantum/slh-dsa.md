# SLH-DSA — FIPS 205

SLH-DSA is the Stateless Hash-Based Digital Signature Algorithm standardized in NIST
FIPS 205. Its hash-based design provides a mathematically different post-quantum signature
family from ML-DSA.

CryptoLab exposes all twelve standardized SHA-2 and SHAKE parameter sets through
OpenSSL 3.5+ EVP.

## Parameter sets and sizes

| Parameter set | Hash family | Goal | Category | Raw public key | Raw private key | Signature |
|---|---|---|---:|---:|---:|---:|
| SLH-DSA-SHA2-128s | SHA-2 | small | 1 | 32 B | 64 B | 7856 B |
| SLH-DSA-SHA2-128f | SHA-2 | fast | 1 | 32 B | 64 B | 17088 B |
| SLH-DSA-SHA2-192s | SHA-2 | small | 3 | 48 B | 96 B | 16224 B |
| SLH-DSA-SHA2-192f | SHA-2 | fast | 3 | 48 B | 96 B | 35664 B |
| SLH-DSA-SHA2-256s | SHA-2 | small | 5 | 64 B | 128 B | 29792 B |
| SLH-DSA-SHA2-256f | SHA-2 | fast | 5 | 64 B | 128 B | 49856 B |
| SLH-DSA-SHAKE-128s | SHAKE | small | 1 | 32 B | 64 B | 7856 B |
| SLH-DSA-SHAKE-128f | SHAKE | fast | 1 | 32 B | 64 B | 17088 B |
| SLH-DSA-SHAKE-192s | SHAKE | small | 3 | 48 B | 96 B | 16224 B |
| SLH-DSA-SHAKE-192f | SHAKE | fast | 3 | 48 B | 96 B | 35664 B |
| SLH-DSA-SHAKE-256s | SHAKE | small | 5 | 64 B | 128 B | 29792 B |
| SLH-DSA-SHAKE-256f | SHAKE | fast | 5 | 64 B | 128 B | 49856 B |

The `s` parameter sets prioritize smaller signatures; the `f` parameter sets prioritize
speed. Signature sizes remain substantially larger than ML-DSA and current classical
signatures.

## Commands

```bash
uv run cryptolab post-quantum slh-dsa parameters
uv run cryptolab post-quantum slh-dsa generate SLH-DSA-SHAKE-128s \
  --private-key-out private.pem --public-key-out public.pem
uv run cryptolab post-quantum slh-dsa sign SLH-DSA-SHAKE-128s \
  --private-key-file private.pem --message-text "CryptoLab" \
  --signature-out signature.bin
uv run cryptolab post-quantum slh-dsa verify SLH-DSA-SHAKE-128s \
  --public-key-file public.pem --message-text "CryptoLab" \
  --signature-file signature.bin
```

An optional context can be supplied when the backend supports the standardized pure
SLH-DSA context operation. The same 255-byte bound used for the signature context is
enforced by CryptoLab.

## Why both ML-DSA and SLH-DSA exist in CryptoLab

The project intentionally includes both standardized signature families. ML-DSA is a
module-lattice signature scheme; SLH-DSA is hash-based. Keeping both makes the comparison
of assumptions, key sizes, signature sizes, and engineering tradeoffs explicit without
turning CryptoLab into a catalogue of every historical PQC candidate.
