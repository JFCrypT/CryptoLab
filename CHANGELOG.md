# Changelog

All notable changes to CryptoLab will be documented in this file.

CryptoLab uses one initial public release, version 1.0.0. No public pre-release is
planned.

## [Unreleased]

No changes are documented after version 1.0.0.

## [1.0.0] - 2026-08-02

### Added

- Repository baseline based on Python, uv, Typer, Rich, pytest, Hypothesis, Ruff, mypy,
  pre-commit, and MkDocs.
- Formal project metadata, contribution, security, citation, and documentation policies.
- Integer arithmetic educational module.
- CLI commands for Euclidean division, divisibility, divisors, primality testing,
  factorization, gcd, lcm, Euclidean traces, and extended gcd.
- Human, JSON, and LaTeX renderers for the implemented commands.
- Automated unit, property, CLI, and packaging tests for the implemented scope.
- Linear Diophantine equation solving, reduction, verification, and complete parameterized
  solution families.
- Canonical modular operations, fast modular exponentiation, inverses, units, and non-zero
  zero divisors.
- Linear congruence solving and the generalized Chinese Remainder Theorem.
- Algebraic descriptions of `Z_n`, additive and multiplicative element orders, generated
  subgroups, group generators, and primitive roots modulo a prime.
- Built-in Latin and Spanish uppercase alphabets plus strict custom JSON alphabet loading.
- Caesar encryption, decryption, modular transformation tables, exhaustive key enumeration,
  and basic character-frequency analysis.
- Vigenère encryption, decryption, and repeated-key alignment with explicit unknown-symbol
  behavior.
- Polybius grid construction, canonical coordinate tokens, preserved Unicode tokens,
  encryption, decryption, and coordinate validation.
- Documentation and automated tests for algebraic structures and classical ciphers.
- Strict binary, hexadecimal, UTF-8, and file byte-input helpers.
- XOR truth tables, equal-length bitwise XOR, and equal-length bytewise XOR with structured
  traces.
- Educational Vernam encryption and decryption plus explicit One-Time Pad requirements.
- Fibonacci right-shift LFSR parsing, generation, state transitions, diagrams, and constant-
  memory period detection under one fixed convention.
- Elementary binary-sequence period, balance, cyclic-run, and periodic-autocorrelation
  analysis.
- Controlled Caesar brute-force and Vernam key-reuse laboratories backed by existing public
  modules.
- Documentation and automated tests for XOR, Vernam, One-Time Pad requirements, LFSRs,
  sequence analysis, and the two implemented laboratories.
- Runtime integration with the established `cryptography` library for modern symmetric
  primitives.
- AES-128 and AES-256 encryption and decryption in ECB, CBC, CFB-128, OFB, CTR, GCM, and
  XTS modes with strict parameter validation.
- Explicit PKCS#7 padding support for ECB and CBC, fixed GCM nonce and tag formats, and
  fixed XTS key and tweak representations.
- ChaCha20-Poly1305 authenticated encryption and authenticated decryption.
- Contextual AES-mode and AES-GCM versus ChaCha20-Poly1305 comparison commands.
- Controlled AES-ECB pattern-leakage laboratory.
- NIST, IEEE, and RFC vector tests for modern symmetric constructions plus round-trip,
  property-based, invalid-input, and authentication-failure tests.
- Detailed modern symmetric documentation and architecture decision record.
- SHA-256 and SHA3-256 hashing for UTF-8 text, canonical hexadecimal bytes, and
  incrementally processed files.
- Full digest verification with constant-time comparison and structured avalanche-effect
  visualization.
- Contextual SHA-256 versus SHA3-256 and hash-versus-HMAC comparison commands.
- Full-length HMAC-SHA-256 generation and verification with RFC 4231 vectors.
- Staged HKDF-SHA-256 extraction and expansion, PRK and OKM inspection, omitted-salt
  handling, output-length enforcement, and RFC 5869 vectors.
- Hashing, HMAC, and HKDF documentation plus architecture decision record.
- Educational textbook RSA key construction from manual or generated small primes, including
  Euler totient, Carmichael function, Euler- and Carmichael-based private exponents, CRT
  parameters, modular-exponentiation traces, and direct/CRT decryption cross-checks.
- Unsigned big-endian integer-to-bytes and bytes-to-integer conversion commands.
- Library-backed RSA key generation and local PKCS#8/SubjectPublicKeyInfo PEM serialization.
- RSA-OAEP encryption and decryption with SHA-256, MGF1-SHA-256, explicit message-size
  limits, and generic decoding failure handling.
- RSA-PSS signing and verification with SHA-256, MGF1-SHA-256, and a fixed 32-byte salt.
- Contextual comparison of textbook RSA, RSA-OAEP, and RSA-PSS plus hybrid-encryption
  explanation, documentation, tests, and architecture decision record.
- Educational finite-field Diffie-Hellman over bounded prime fields with generator
  validation, element-order inspection, modular-exponentiation traces, shared-secret
  verification, and HKDF-SHA-256 session-key derivation.
- The fourth controlled laboratory: unauthenticated Diffie-Hellman man-in-the-middle with
  substituted public values, two attacker-known channel keys, documentation, tests, and an
  architecture decision record.
- Educational short-Weierstrass elliptic-curve arithmetic over bounded prime fields,
  including non-singularity checks, point enumeration, infinity, negation, addition,
  doubling, double-and-add scalar multiplication, point orders, and generated subgroups.
- Library-backed X25519 key generation, PKCS#8/SubjectPublicKeyInfo serialization, RFC 7748
  vector validation, bilateral shared-secret computation, all-zero rejection, and
  HKDF-SHA-256 derivation.
- Library-backed Ed25519 key generation, RFC 8032 vector validation, deterministic signing,
  verification, and invalid-signature handling.
- Contextual finite-field Diffie-Hellman versus X25519 and RSA-PSS versus Ed25519 versus
  HMAC-SHA-256 comparisons, documentation, tests, and an architecture decision record.
- Consolidated cryptographic terminology, security-service distinctions, and every required
  version 1.0.0 comparison.
- Release traceability, release acceptance criteria, and a documented manual release process.
- A repository-owned release checker covering metadata, scope guardrails, required files,
  wheel contents, source-distribution contents, and secret-file exclusions.
- Optional dynamic direct SageMath cross-validation for selected educational operations,
  isolated from the normal runtime package and mandatory release path.
- Release-hardening tests and CI checks for metadata, distribution contents, and isolated
  wheel execution.

### Fixed

- Corrected the initial Ruff and mypy configuration and implementation issues.
- Removed the deprecated license classifier while retaining PEP 639 license metadata.
- Clarified that pre-commit hook installation requires an initialized Git repository.
- Finalized type-only imports and dataclass narrowing for clean Ruff and mypy checks.

[Unreleased]: https://github.com/JFCrypT/CryptoLab/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/JFCrypT/CryptoLab/releases/tag/v1.0.0
