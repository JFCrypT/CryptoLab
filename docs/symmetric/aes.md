# AES and its modes

## Implementation category

All modern AES operations in CryptoLab are **library-backed**. The project delegates the
primitive and mode processing to `cryptography` and exposes parameters, outputs, warnings,
and comparisons for study.

AES uses a fixed 128-bit block size. CryptoLab includes AES-128 and AES-256, where the number
refers to the key size.

## Commands

```bash
cryptolab symmetric aes encrypt MODE [OPTIONS]
cryptolab symmetric aes decrypt MODE [OPTIONS]
cryptolab symmetric aes compare-modes
```

The accepted modes are:

```text
ecb
cbc
cfb-128
ofb
ctr
gcm
xts
```

Inputs use exactly one of `--plaintext-text`, `--plaintext-hex`, or `--plaintext-file` for
encryption. Decryption uses exactly one of `--ciphertext-hex` or `--ciphertext-file`.

## ECB

Electronic Codebook independently encrypts every block. Equal plaintext blocks encrypted
under one key produce equal ciphertext blocks. This deterministic equality leakage makes ECB
unsuitable for structured multi-block confidential data.

ECB requires block-aligned input when padding is disabled. CryptoLab may apply PKCS#7 when
`--padding pkcs7` is selected, but padding does not repair ECB's structural leakage.

```bash
cryptolab symmetric aes encrypt ecb \
  --key-hex 2b7e151628aed2a6abf7158809cf4f3c \
  --plaintext-hex 6bc1bee22e409f96e93d7e117393172a
```

## CBC

Cipher Block Chaining XORs each plaintext block with the previous ciphertext block before
encryption. The first block uses a 16-byte IV. A fresh unpredictable IV is required for each
encryption under a key.

CBC requires padding for non-aligned messages. CryptoLab supports PKCS#7 explicitly:

```bash
cryptolab symmetric aes encrypt cbc \
  --key-hex 2b7e151628aed2a6abf7158809cf4f3c \
  --iv-hex 000102030405060708090a0b0c0d0e0f \
  --padding pkcs7 \
  --plaintext-text "CryptoLab"
```

CBC provides confidentiality only. It does not authenticate the IV or ciphertext.

## CFB-128

Cipher Feedback converts AES into a stream-like construction. CryptoLab fixes the segment
size at 128 bits. It requires a fresh unpredictable 16-byte IV for each encryption under a
key, requires no padding, and has sequential feedback.

CFB is retained for didactic and comparative coverage. Recent `cryptography` versions classify
it as a legacy mode and expose it through the decrepit namespace.

## OFB

Output Feedback repeatedly encrypts internal state to generate a keystream. It requires a
unique 16-byte IV, uses no padding, and does not authenticate data. Sender and receiver must
remain synchronized.

OFB is retained for didactic and comparative coverage and is treated as a legacy mode by
recent `cryptography` versions.

## CTR

Counter mode encrypts successive counter blocks to generate a keystream. CryptoLab receives
the complete initial 16-byte counter block through `--counter-hex`; it does not silently split
that block into nonce and counter fields.

CTR requires no padding, permits parallel processing and random access, and provides no
authentication. Reusing a counter sequence with the same key reveals relationships between
plaintexts.

## GCM

Galois/Counter Mode is authenticated encryption with associated data. It produces:

- ciphertext;
- a 16-byte authentication tag;
- authentication over ciphertext and optional AAD.

CryptoLab fixes the nonce at 12 bytes and uses the one-shot `AESGCM` API.

```bash
cryptolab symmetric aes encrypt gcm \
  --key-hex 00000000000000000000000000000000 \
  --nonce-hex 000000000000000000000000 \
  --plaintext-hex 00000000000000000000000000000000 \
  --aad-text "header"
```

Authenticated decryption must receive the same key, nonce, tag, and AAD. A mismatch returns
an authentication failure and no plaintext.

Nonce reuse with one key is catastrophic and can break both confidentiality and
authentication.

## XTS

XTS is designed for confidentiality of storage data units such as sectors. It uses:

- two AES keys, concatenated in the CLI key value;
- a 16-byte tweak identifying a data-unit position;
- no authentication tag.

A 32-byte XTS key means XTS-AES-128. A 64-byte XTS key means XTS-AES-256. The component
keys must not be identical. A data unit must contain at least 16 bytes.

```bash
cryptolab symmetric aes encrypt xts \
  --key-hex 2718281828459045235360287471352631415926535897932384626433832795 \
  --tweak-hex 00000000000000000000000000000000 \
  --plaintext-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

XTS is not a general message-encryption mode and does not authenticate modified sectors.

## Validation

The automated tests include:

- NIST SP 800-38A examples for AES-128 ECB, CBC, CFB-128, OFB, and CTR;
- a NIST SP 800-38D AES-GCM example;
- an IEEE/NIST XTS-AES example;
- AES-256 examples;
- PKCS#7 round trips and invalid-padding tests;
- authenticated-decryption failure tests;
- boundary and invalid-parameter tests.

Passing these checks is reproducible validation, not certification.
