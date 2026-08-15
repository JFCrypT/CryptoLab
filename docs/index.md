# CryptoLab — Applied Cryptography Laboratory

CryptoLab connects cryptographic mathematics, transparent educational implementations,
modern library-backed cryptographic operations, lightweight visualization, reproducible
validation, algorithm comparison, and four controlled cryptanalysis laboratories.

Version 1.0.0 defines the approved initial public scope. Version 1.1.0 preserves that scope
and adds the explicitly approved NIST-standardized post-quantum extension: ML-KEM, ML-DSA,
and SLH-DSA. Each validated version tag and its distributions define a public release.

## Documentation model

The repository README is the complete self-contained entry point. This manual provides the
more detailed mathematical, architectural, cryptographic, laboratory, comparison, and
validation material.

Start with:

- **Cryptographic foundations** for terminology and security-service boundaries;
- **Required comparisons** for one consolidated algorithm/construction comparison;
- **Release traceability** for the link between scope, code, documentation, and tests;
- **Release acceptance** for the mandatory version 1.1.0 criteria;
- **Post-quantum cryptography** for FIPS 203, FIPS 204, FIPS 205, and the bounded PQC foundations.

## Implemented scope

CryptoLab includes integer, Diophantine, modular, and algebraic foundations; classical
ciphers; XOR, Vernam, OTP requirements, LFSRs, and sequence analysis; all approved AES modes
and ChaCha20-Poly1305; SHA-256, SHA3-256, HMAC-SHA-256, and HKDF-SHA-256; educational and
applied RSA; finite-field Diffie-Hellman; educational elliptic-curve arithmetic; X25519;
Ed25519; ML-KEM, ML-DSA, and SLH-DSA; and exactly four controlled local laboratories.

Educational modules expose mathematics and intermediate states. Modern 1.0.0 primitives are backed by `cryptography`; standardized 1.1.0 PQC operations are delegated to OpenSSL 3.5+ EVP. Neither category is presented as certification, formal
verification, independent auditing, or universal production approval.

SageMath cross-validation is optional and directly compares supported CryptoLab calculations
with an isolated SageMath reference process. It is not part of the normal runtime package or
mandatory release gate.
