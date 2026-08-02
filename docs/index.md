# CryptoLab — Applied Cryptography Laboratory

CryptoLab connects cryptographic mathematics, transparent educational implementations,
modern library-backed cryptographic operations, lightweight visualization, reproducible
validation, algorithm comparison, and four controlled cryptanalysis laboratories.

Version 1.0.0 implements the complete approved initial scope. The validated `v1.0.0` tag and
its distributions define the public release; earlier history is development history rather
than a public pre-release.

## Documentation model

The repository README is the complete self-contained entry point. This manual provides the
more detailed mathematical, architectural, cryptographic, laboratory, comparison, and
validation material.

Start with:

- **Cryptographic foundations** for terminology and security-service boundaries;
- **Required comparisons** for one consolidated algorithm/construction comparison;
- **Release traceability** for the link between scope, code, documentation, and tests;
- **Release acceptance** for the mandatory version 1.0.0 criteria.

## Implemented scope

CryptoLab includes integer, Diophantine, modular, and algebraic foundations; classical
ciphers; XOR, Vernam, OTP requirements, LFSRs, and sequence analysis; all approved AES modes
and ChaCha20-Poly1305; SHA-256, SHA3-256, HMAC-SHA-256, and HKDF-SHA-256; educational and
applied RSA; finite-field Diffie-Hellman; educational elliptic-curve arithmetic; X25519;
Ed25519; and exactly four controlled local laboratories.

Educational modules expose mathematics and intermediate states. Modern primitives are
backed by `cryptography`. Neither category is presented as certification, formal
verification, independent auditing, or universal production approval.

SageMath cross-validation is optional and directly compares supported CryptoLab calculations
with an isolated SageMath reference process. It is not part of the normal runtime package or
mandatory release gate.
