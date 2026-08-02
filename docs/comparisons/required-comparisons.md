# Consolidated required comparisons

This page consolidates every comparison required for version 1.0.0. Detailed derivations
and command examples remain in the topic-specific pages.

## Educational versus library-backed implementations

| Property | Educational implementation | Library-backed implementation |
|---|---|---|
| Primary goal | Transparency and inspectable mathematics | Correct use of established modern APIs |
| Typical parameters | Small and deliberately inspectable | Standard modern parameter sizes |
| Intermediate values | Often exposed | Normally hidden by the library abstraction |
| Side-channel posture | Not claimed; may branch on sensitive values | Delegated partly to the library, without a CryptoLab production claim |
| CryptoLab examples | Euclid, CRT, Caesar, LFSR, textbook RSA, finite-field DH, tiny ECC | AES, ChaCha20-Poly1305, RSA-OAEP, RSA-PSS, X25519, Ed25519 |
| Permitted use | Study, explanation, and local demonstrations | Applied API education, not universal production approval |

## Block ciphers versus stream ciphers

A block cipher transforms fixed-size blocks under a key. A stream cipher produces a
keystream that is combined with data, commonly by XOR. Modes such as CTR, OFB, and CFB make
a block cipher operate in a stream-like way. AES remains a 128-bit block cipher in every
mode; ChaCha20 is a stream cipher inside the ChaCha20-Poly1305 AEAD construction.

Stream-like encryption avoids message padding, but keystream reuse can reveal relations
between plaintexts. Neither category inherently authenticates data.

## AES-128 versus AES-256

| Property | AES-128 | AES-256 |
|---|---|---|
| Block size | 128 bits | 128 bits |
| Key size | 128 bits | 256 bits |
| Rounds | 10 | 14 |
| Padding | Determined by the mode, not the key size | Determined by the mode, not the key size |
| CryptoLab status | Library-backed | Library-backed |

The larger key does not change the AES block size. Selection depends on policy, platform,
interoperability, performance, and the surrounding system rather than a universal ranking.

## AES modes

| Mode | Purpose | IV, nonce, counter, or tweak | Padding | Authentication | Parallel/random access | Principal misuse risk |
|---|---|---|---|---|---|---|
| ECB | Educational block comparison | None | Aligned blocks or PKCS#7 | No | Independent blocks | Repeated-block pattern leakage |
| CBC | Legacy message confidentiality | Unpredictable 128-bit IV | PKCS#7 for partial blocks | No | Decryption parallelizable; poor random access | IV misuse and unauthenticated ciphertext |
| CFB-128 | Legacy stream-like confidentiality | Unique 128-bit IV under the key | None | No | Sequential feedback | IV reuse and missing authentication |
| OFB | Synchronous stream-like confidentiality | Unique 128-bit IV under the key | None | No | Keystream sequential; positioning possible | Keystream reuse and synchronization loss |
| CTR | Parallel stream-like confidentiality | Non-repeating 128-bit initial counter block | None | No | Parallel and random access | Counter-sequence reuse |
| GCM | Authenticated message encryption | Unique 96-bit nonce under the key | None | Yes, including AAD | Parallelizable | Nonce reuse and ignored tag failures |
| XTS | Storage data-unit confidentiality | 128-bit tweak identifying the data unit | No message padding | No | Data-unit oriented | Use as general message encryption and missing integrity |

### Ciphertext-error behavior

- **ECB:** damage is confined to the corresponding plaintext block, but structure remains
  exposed.
- **CBC:** one damaged ciphertext block garbles its plaintext block and flips corresponding
  bits in the next plaintext block.
- **CFB-128:** damage affects the current segment and temporarily propagates through feedback.
- **OFB and CTR:** a ciphertext-bit change flips the corresponding plaintext bit without
  further propagation; neither mode authenticates the change.
- **GCM:** any unauthorized change must cause tag verification to fail, and unauthenticated
  plaintext must not be released.
- **XTS:** corruption affects the corresponding storage region, but no authentication failure
  is available.

## AES-GCM versus ChaCha20-Poly1305

Both are AEAD constructions with a 96-bit nonce and a 128-bit tag in CryptoLab. AES-GCM
combines AES counter mode with a Galois-field authenticator; ChaCha20-Poly1305 combines a
stream cipher with Poly1305. AES-GCM often benefits from AES hardware support, while
ChaCha20-Poly1305 can be attractive where such acceleration is absent. Nonce reuse under one
key is a critical failure for both. Neither is universally superior.

## SHA-256 versus SHA3-256

| Property | SHA-256 | SHA3-256 |
|---|---|---|
| Digest length | 256 bits | 256 bits |
| Family | SHA-2 | SHA-3 |
| Internal model | Iterated compression construction | Sponge construction based on Keccak |
| Keyed authentication | No | No |
| CryptoLab implementation | Standard-library backed | Standard-library backed |

Equal digest size does not imply equal internal construction. The API task is similar, but
protocol requirements and interoperability determine selection.

## Hash functions, HMAC, and digital signatures

| Property | Hash | HMAC-SHA-256 | RSA-PSS / Ed25519 |
|---|---|---|---|
| Secret key required | No | Shared secret | Private signing key |
| Verification | Anyone recomputes | Only a party with the shared key | Anyone with the public key |
| Integrity against active replacement | No, by itself | Yes under the shared-key model | Yes under the signature-key model |
| Public attribution | No | No | Technically possible under the public-key identity model |
| Confidentiality | No | No | No |

HMAC is a MAC rather than a digital signature. A bare hash is not a MAC.

## Finite-field Diffie-Hellman versus X25519

| Property | Educational finite-field DH | X25519 |
|---|---|---|
| Mathematical setting | Multiplicative subgroup modulo a prime | Montgomery-form elliptic-curve scalar multiplication |
| CryptoLab parameters | Tiny, inspectable, insecure | Modern fixed 32-byte keys through `cryptography` |
| Public-value validation | Explicit educational generator/order checks | High-level library API and all-zero shared-secret rejection |
| Output handling | Fixed-width integer encoding then HKDF-SHA-256 | 32-byte shared secret then HKDF-SHA-256 |
| Authentication | None by itself | None by itself |
| CryptoLab status | Educational | Library-backed |

Both perform key agreement rather than encryption. The MITM laboratory demonstrates why an
unauthenticated exchange remains vulnerable even when a KDF is applied afterward.

## RSA-PSS versus Ed25519

| Property | RSA-PSS | Ed25519 |
|---|---|---|
| Underlying family | Integer factorization / RSA | Edwards-curve signatures |
| CryptoLab key choices | RSA 2048, 3072, or 4096 bits | Fixed Ed25519 key format |
| Signature length | Equal to RSA modulus length | 64 bytes |
| Randomized signing | Yes, 32-byte PSS salt | Deterministic for a key and message |
| Hash behavior in CryptoLab | SHA-256 and MGF1-SHA-256 | Defined internally by Ed25519 |
| Implementation | `cryptography` | `cryptography` |

They provide the same broad service but differ in assumptions, encoding, key size,
signature size, randomness, performance context, and ecosystem requirements. Neither is
universally superior.

## Educational RSA versus applied RSA

| Construction | Purpose | Padding/encoding | Randomized | Security status |
|---|---|---|---|---|
| Textbook RSA | Expose modular arithmetic, inverses, and CRT | None | No | Educational and insecure for real data |
| RSA-OAEP | Encrypt or transport a short secret | OAEP with SHA-256 and MGF1-SHA-256 | Yes | Library-backed applied example |
| RSA-PSS | Sign and verify messages | PSS with SHA-256, MGF1-SHA-256, 32-byte salt | Yes | Library-backed applied example |

Encryption and signing are not interchangeable. RSA-OAEP has a strict message-size limit
and belongs in short-secret or hybrid-encryption contexts; CryptoLab explains hybrid
encryption but does not define a production envelope format.
