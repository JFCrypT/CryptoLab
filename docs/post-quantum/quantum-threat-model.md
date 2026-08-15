# Quantum threat model

Post-quantum cryptography addresses the possibility that a sufficiently capable
cryptographically relevant quantum computer could invalidate important assumptions used by
current public-key cryptography.

## Shor's algorithm: consequence for CryptoLab

Shor's algorithm is relevant because it gives polynomial-time quantum algorithms for integer
factorization and discrete logarithms. Consequently, the assumptions underlying RSA,
finite-field Diffie-Hellman, X25519, Ed25519, and the educational elliptic-curve material are
not regarded as post-quantum assumptions.

CryptoLab does **not** implement or simulate Shor's algorithm. Its role in version 1.1.0 is a
threat-model explanation that motivates the transition from classical public-key mechanisms
to standardized PQC.

## Grover's algorithm: consequence for symmetric cryptography

Grover's algorithm gives a generic quadratic speedup for unstructured search. This changes
security-margin reasoning for symmetric keys and hash preimages but does not make AES,
SHA-2, SHA-3, HMAC, or HKDF obsolete in the same way that Shor's algorithm threatens RSA
and discrete-logarithm systems.

CryptoLab does not implement Grover's algorithm. The existing AES-256 and modern hash
material remain useful when discussing conservative post-quantum security margins.

## Harvest now, decrypt later

Long-lived confidential data can motivate migration before a cryptographically relevant
quantum computer exists. An adversary may record traffic today and attempt to recover
protected secrets later if the public-key establishment mechanism becomes breakable.

This is one reason a KEM such as ML-KEM matters independently of post-quantum signature
migration.

## CryptoLab boundary

The label *post-quantum* in CryptoLab means that ML-KEM, ML-DSA, and SLH-DSA were
designed for security against known classical and quantum attacks under their documented
assumptions. It is not a claim of unconditional security, formal verification, certification,
or immunity to implementation flaws.
