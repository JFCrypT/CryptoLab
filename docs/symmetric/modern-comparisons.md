# Modern symmetric comparisons

## AES modes

| Mode | Primary purpose | Padding | Authentication | Parallelization | Random access | Main misuse risk |
|---|---|---|---|---|---|---|
| ECB | block-level teaching comparison | aligned blocks or PKCS#7 | no | encrypt/decrypt | block-level | deterministic pattern leakage |
| CBC | legacy message confidentiality | PKCS#7 for partial blocks | no | decryption only | poor | predictable/reused IV and unauthenticated ciphertext |
| CFB-128 | legacy stream-like confidentiality | none | no | limited | limited | IV reuse and missing authentication |
| OFB | synchronous stream-like confidentiality | none | no | keystream sequential | possible with state positioning | IV reuse and synchronization loss |
| CTR | parallel stream-like confidentiality | none | no | yes | yes | counter-sequence reuse |
| GCM | authenticated message encryption | none | yes | yes | not independently authenticated per block | nonce reuse |
| XTS | storage data-unit confidentiality | no message padding | no | per data unit | sector-oriented | use outside storage and missing integrity |

No entry is universally best. Purpose, platform, protocol, parameter allocation, and misuse
resistance determine suitability.

## AES-128 versus AES-256

Both use a 128-bit block size. AES-256 uses a 256-bit key and a larger key schedule. The key
size difference must not be described as a block-size difference. CryptoLab exposes both
through the same library-backed mode layer.

## AES-GCM versus ChaCha20-Poly1305

| Property | AES-GCM | ChaCha20-Poly1305 |
|---|---|---|
| CryptoLab key size | 128 or 256 bits | 256 bits |
| Nonce | 96 bits | 96 bits |
| Tag | 128 bits | 128 bits |
| Structure | AES-CTR plus Galois-field authenticator | ChaCha20 stream cipher plus Poly1305 authenticator |
| Typical performance context | often strong with AES hardware support | often attractive without AES acceleration |
| Critical misuse | nonce reuse under one key | nonce reuse under one key |
| Implementation | `cryptography.AESGCM` | `cryptography.ChaCha20Poly1305` |

Both are AEAD constructions. Neither result implies certification or universal superiority.

```bash
cryptolab symmetric aes compare-modes
cryptolab symmetric compare-aead
```
