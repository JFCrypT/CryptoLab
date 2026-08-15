# ML-KEM — FIPS 203

ML-KEM is the Module-Lattice-Based Key-Encapsulation Mechanism standardized by NIST in
FIPS 203. CryptoLab exposes all three standardized parameter sets through OpenSSL 3.5+ EVP.

## Parameter sets

| Parameter set | NIST category | Raw public key | Raw private key | Ciphertext | Shared secret |
|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | 1 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

The raw standardized sizes are shown for comparison. Serialized PEM files contain
additional ASN.1/encoding overhead and therefore have different byte lengths.

## KEM workflow

A KEM has three conceptual operations:

1. the receiver generates a key pair;
2. the sender encapsulates using the public key and obtains a ciphertext plus a shared
   secret;
3. the receiver decapsulates the ciphertext using the private key and obtains the same
   shared secret.

ML-KEM is not bulk data encryption. A protocol uses the resulting shared key material for
subsequent symmetric cryptography, usually through protocol-defined key derivation.

## CryptoLab commands

```bash
uv run cryptolab post-quantum ml-kem parameters
uv run cryptolab post-quantum ml-kem generate ML-KEM-768 \
  --private-key-out private.pem --public-key-out public.pem
uv run cryptolab post-quantum ml-kem encapsulate ML-KEM-768 \
  --public-key-file public.pem --ciphertext-out ciphertext.bin \
  --shared-secret-out sender-secret.bin
uv run cryptolab post-quantum ml-kem decapsulate ML-KEM-768 \
  --private-key-file private.pem --ciphertext-file ciphertext.bin \
  --shared-secret-out receiver-secret.bin
```

The private key and optional shared-secret output use restrictive file permissions. The
ciphertext and public key are not secret.

## Backend and validation

The implementation category is `library-backed`. CryptoLab validates standardized output
lengths and performs generated encapsulation/decapsulation round trips in the native PQC CI
job. The release does not claim NIST module validation or independent certification merely
because FIPS-defined algorithms and sizes are used.
