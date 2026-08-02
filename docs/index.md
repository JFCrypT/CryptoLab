# CryptoLab — Applied Cryptography Laboratory

CryptoLab connects cryptographic mathematics, transparent educational implementations,
modern library-backed cryptographic operations, lightweight visualization, reproducible
validation, algorithm comparison, and four controlled cryptanalysis laboratories.

The project is being developed toward a single initial public release, version 1.0.0. The
complete approved scope must be implemented, tested, documented, and reviewed before the
release tag is created.

## Documentation model

The repository README is the complete self-contained entry point. This manual provides the
more detailed mathematical, architectural, cryptographic, laboratory, comparison, and
validation material.

## Current internal implementation status

The implemented foundation currently provides:

- integer arithmetic, Euclidean traces, Bézout coefficients, primality, and factorization;
- complete linear Diophantine equation solving and verification;
- canonical modular operations and fast exponentiation;
- units, inverses, non-zero zero divisors, linear congruences, and generalized CRT;
- structural analysis of `Z_n`, additive and multiplicative element orders, generated
  subgroups, group generators, and primitive roots modulo a prime;
- configurable ordered alphabets;
- Caesar encryption, decryption, tables, complete key enumeration, and frequency counts;
- Vigenère encryption, decryption, and repeated-key alignment;
- Polybius grid construction, coordinate validation, encryption, and decryption;
- XOR truth tables, bitwise and bytewise XOR, Vernam encryption and decryption, and strict
  One-Time Pad requirements;
- the fixed Fibonacci right-shift LFSR convention, cycle detection, state traces, period,
  balance, cyclic runs, and periodic autocorrelation;
- the controlled Caesar brute-force, Vernam key-reuse, and AES-ECB pattern-leakage
  laboratories;
- library-backed AES-128 and AES-256 in ECB, CBC, CFB-128, OFB, CTR, GCM, and XTS modes;
- library-backed ChaCha20-Poly1305 authenticated encryption;
- modern symmetric comparison tables, published vectors, and authentication-failure tests;
- library-backed SHA-256 and SHA3-256 for text, hexadecimal bytes, and incremental file hashing;
- full digest verification and byte-level avalanche visualization;
- HMAC-SHA-256 generation and constant-time verification;
- staged HKDF-SHA-256 extraction, PRK inspection, expansion, OKM generation, and RFC vectors;
- educational textbook RSA key construction, Euler and Carmichael private exponents, CRT
  parameters, integer/byte conversion, and direct/CRT decryption cross-checks;
- library-backed RSA-OAEP, RSA-PSS, RSA key generation, and PEM serialization;
- RSA purpose, key-direction, message-size, and hybrid-encryption comparisons;
- educational finite-field Diffie-Hellman with generator validation, shared-secret
  computation, HKDF-SHA-256 derivation, and explicit key-agreement limitations;
- the controlled unauthenticated Diffie-Hellman man-in-the-middle laboratory, completing
  the four approved local laboratories;
- human, JSON, and LaTeX interfaces with automated validation.

These are internal development milestones only. They do not constitute a public pre-release.
