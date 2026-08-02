# Release status and future scope

CryptoLab has one initial public release: version 1.0.0. The milestones below describe the
internal implementation order only and do not define pre-releases.

1. **Completed:** repository, architecture, conventions, and integer arithmetic.
2. **Completed:** linear Diophantine equations and modular arithmetic.
3. **Completed:** algebraic structures, cyclic groups, and classical cryptography.
4. **Completed:** XOR, Vernam, One-Time Pad requirements, LFSR, elementary sequence
   analysis, and the Caesar and Vernam controlled laboratories.
5. **Completed:** AES-128, AES-256, ECB, CBC, CFB-128, OFB, CTR, GCM, XTS,
   ChaCha20-Poly1305, mode comparisons, and the ECB pattern-leakage laboratory.
6. **Completed:** SHA-256, SHA3-256, HMAC-SHA-256, HKDF-SHA-256, file hashing,
   digest comparison, hash-versus-MAC comparison, and avalanche visualization.
7. **Completed:** educational textbook RSA, RSA-OAEP, RSA-PSS, key serialization,
   RSA comparisons, and hybrid-encryption explanation.
8. **Completed:** finite-field Diffie-Hellman and the controlled MITM laboratory.
9. **Completed:** educational elliptic-curve arithmetic, X25519, Ed25519, key-agreement
   comparison, and signature-versus-MAC comparison.
10. **Completed:** comparison consolidation, optional dynamic SageMath cross-validation,
    traceability, documentation consolidation, distribution checks, and release hardening.

The `v1.0.0` tag is created only after the complete acceptance sequence passes on the final
commit. Future additions require explicit approval and must preserve the limited didactic
scope. No additional primitive, attack laboratory, network service, GUI, web application,
PQC module, or production security subsystem is implicitly planned.
