# Cryptographic foundations and security services

CryptoLab uses the following terms consistently. A primitive, construction, or protocol
must not be credited with a security service that it does not actually provide.

## Core disciplines and objects

| Term | Definition used by CryptoLab |
|---|---|
| Cryptology | The broader discipline containing cryptography and cryptanalysis. |
| Cryptography | The design and use of mathematical constructions intended to provide defined security properties. |
| Cryptanalysis | The analysis of cryptographic constructions, including attempts to violate their stated properties or assumptions. |
| Cryptosystem | A defined collection of algorithms, key spaces, inputs, outputs, and correctness rules for a cryptographic task. |
| Cryptographic primitive | A basic algorithmic building block such as a block cipher, hash function, MAC, KDF, or signature scheme. |
| Cryptographic protocol | An ordered interaction that combines primitives, messages, state, and validation rules to achieve a larger goal. |
| Plaintext | Data supplied to an encryption operation before confidentiality protection. |
| Ciphertext | Output of encryption; it is not automatically authenticated. |
| Encryption | A keyed transformation intended to provide confidentiality. |
| Decryption | The inverse or authenticated recovery operation for encrypted data. |
| Key | A parameter selected from a defined key space that controls a cryptographic operation. |
| Key space | The set of keys allowed by a construction. |
| Symmetric key | A secret value shared by parties for symmetric encryption, MAC generation, or another symmetric task. |
| Public key | A value intended for distribution and used for operations such as encryption or signature verification. |
| Private key | A secret asymmetric key used for operations such as decryption, signing, or key agreement. |
| Shared secret | A secret value computed by key-agreement participants; it normally requires a KDF before application use. |
| Key encapsulation mechanism (KEM) | An asymmetric construction in which encapsulation under a public key produces a ciphertext and shared key material, while decapsulation uses the private key to recover corresponding key material. |
| Session key | A key scoped to a defined session, channel, or context. |

## Parameters and encoded data

| Term | Definition and constraint |
|---|---|
| Nonce | A value that must satisfy the uniqueness or unpredictability rule of its construction; it is not necessarily secret. |
| Initialization vector | A mode parameter that initializes encryption state and may require uniqueness, unpredictability, or both. |
| Counter | A non-repeating input sequence used to generate distinct keystream blocks. |
| Tweak | A non-secret value that diversifies a tweakable construction, such as the XTS data-unit identifier. |
| Salt | A usually non-secret value that separates derivations or randomized encodings; its exact requirement depends on the construction. |
| Authentication tag | A fixed-length value checked to detect unauthorized changes under a symmetric authentication key. |
| Associated data | Data authenticated by an AEAD construction but not encrypted. |
| Padding | Reversible formatting added to satisfy a construction's input-length rules; padding alone is not authentication. |
| Keystream | A pseudorandom byte or bit sequence combined with plaintext, commonly through XOR. Reuse may be catastrophic. |

## Hashing, authentication, derivation, and signatures

| Term | Definition used by CryptoLab |
|---|---|
| Hash function | An unkeyed function mapping arbitrary-length input to a fixed-length digest. |
| MAC | A keyed mechanism for message integrity and origin authentication among parties sharing the key. |
| KDF | A mechanism that derives one or more keys from input keying material and context. |
| Digital signature | A private-key operation producing a value verifiable with the corresponding public key. |
| Technical non-repudiation | Evidence attributable through a signature-key model; broader legal non-repudiation also depends on identity, custody, policy, and procedure outside the primitive. |

## Adversaries, models, and assumptions

| Term | Definition used by CryptoLab |
|---|---|
| Adversary | An entity attempting to learn protected data, modify messages, impersonate a party, or violate another stated property. |
| Attack model | The adversary's capabilities, access, observations, and success condition. |
| Security assumption | A computational or operational premise on which the claimed property depends, such as hardness of a number-theoretic problem or nonce uniqueness. |

## Security services

- **Confidentiality** limits disclosure of protected plaintext. Encryption is designed for
  this purpose, but unauthenticated encryption does not automatically detect modification.
- **Integrity** detects unauthorized modification. A bare hash does not provide keyed
  integrity against an active attacker who can replace both message and digest.
- **Authentication** provides evidence about an origin, participant, or message under a
  defined trust model. It may be symmetric, signature-based, or protocol-based.
- **Technical non-repudiation** is associated with asymmetric signatures and key ownership,
  but the primitive alone cannot establish legal identity, exclusive custody, intent, or
  legal effect.

## Operations that must remain distinct

| Operation | Provides | Does not provide by itself |
|---|---|---|
| Symmetric encryption | Confidentiality under a shared key | Integrity, origin authentication, or non-repudiation |
| Asymmetric encryption | Confidentiality or short-secret transport under a public key | A digital signature or participant authentication |
| Authenticated encryption | Confidentiality plus ciphertext/AAD integrity under a shared key | Public verifiability or non-repudiation |
| Key agreement | A shared secret between participants | Encryption or participant authentication |
| Key encapsulation | Shared key material plus a KEM ciphertext | Bulk message encryption or participant authentication |
| Hashing | A deterministic digest | Keyed message authentication |
| HMAC | Shared-key integrity and message authentication | Public verification or digital signatures |
| KDF | Context-bound key material | Entropy not present in its input or participant authentication |
| Digital signature | Publicly verifiable message authentication under a key model | Confidentiality |

CryptoLab examples repeatedly expose these boundaries. In particular, unauthenticated
Diffie-Hellman and X25519 do not authenticate participants; textbook RSA is not applied
encryption; HMAC is not a signature; XTS is not authenticated message encryption; and a
passing test vector is validation evidence rather than certification.

## Post-quantum cryptography

CryptoLab distinguishes a *post-quantum design* from a generic modern primitive. RSA,
finite-field Diffie-Hellman, elliptic-curve cryptography, X25519, and Ed25519 rely on
factorization or discrete-logarithm assumptions threatened by Shor's algorithm. Version 1.1.0
adds ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) as library-backed
standardized alternatives. The label does not imply unconditional security, certification, or
protocol-level migration correctness.
