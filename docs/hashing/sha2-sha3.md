# SHA-256 and SHA3-256

CryptoLab includes SHA-256 and SHA3-256 as library-backed 256-bit hash functions. Both map an
arbitrary byte string to a 32-byte digest, but they belong to different construction families.

## Included operations

```bash
cryptolab hashing digest sha256 --message-text "abc"
cryptolab hashing digest sha3-256 --message-hex 616263
cryptolab hashing digest sha256 --message-file artifact.bin
```

The file form processes the input incrementally. Text is encoded strictly as UTF-8 and
hexadecimal input uses the repository-wide canonical format.

## Digest verification

```bash
cryptolab hashing verify sha256 \
  --message-text "abc" \
  --digest-hex ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Verification requires a complete 32-byte digest and uses `hmac.compare_digest`. A mismatch
returns exit code `4`.

A digest can detect an accidental or adversarial change only when the expected digest is itself
obtained through a trusted channel. Anyone can recompute an unkeyed digest, so a digest alone
does not authenticate a sender.

## SHA-2 versus SHA-3

```bash
cryptolab hashing compare-hashes
```

| Property | SHA-256 | SHA3-256 |
|---|---|---|
| Output | 256 bits | 256 bits |
| Family | SHA-2 | SHA-3 |
| High-level structure | Iterated compression | Sponge construction |
| Python API | `hashlib.sha256` | `hashlib.sha3_256` |
| Authentication by itself | No | No |

Equal digest length does not imply equal internal construction. CryptoLab does not implement
either construction manually.

## Avalanche visualization

```bash
cryptolab --explain hashing avalanche sha256 \
  --left-text "abc" \
  --right-text "abd"
```

The command measures the input Hamming distance and the digest Hamming distance. It displays
the digest XOR and a byte-level table. A single result demonstrates diffusion behavior but is
not a statistical proof of security.

## Published vectors

The automated tests include the empty string and `abc` vectors for both SHA-256 and SHA3-256.
The SHA-256 behavior is specified by NIST FIPS 180-4 and SHA3-256 by NIST FIPS 202.
Passing these vectors establishes reproducibility against published values; it is not NIST
validation or certification.
