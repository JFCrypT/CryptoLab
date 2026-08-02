# References

The project distinguishes teaching sources, normative sources, and test-vector sources.

## Teaching and background

- Menezes, A. J., van Oorschot, P. C., and Vanstone, S. A. *Handbook of Applied
  Cryptography*. CRC Press, 1996.
- Project teaching notes on integer arithmetic, Diophantine equations, modular arithmetic,
  algebraic structures, classical cryptography, Vernam, LFSRs, RSA, and private-key
  cryptography.
- Project exercise guide examples for Vernam and the polynomials `x^3+x^2+1`,
  `x^4+x^3+1`, and `x^5+x^4+x^3+x+1` under the explicitly documented CryptoLab
  convention.

Teaching sources guide explanations and examples. They do not replace current standards for
modern primitives.

## Normative and validation sources

- Menezes, A. J., van Oorschot, P. C., and Vanstone, S. A. Sections 1.5 and 6.2–6.3 for
  Vernam, feedback shift registers, periods, statistical properties, and the warning that an
  LFSR must not be used alone as a keystream generator.
- NIST FIPS 197, *Advanced Encryption Standard (AES)*.
- NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and
  Techniques*, including the ECB, CBC, CFB-128, OFB, and CTR examples used by the tests.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter
  Mode (GCM) and GMAC*.
- NIST SP 800-38E, *Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode
  for Confidentiality on Storage Devices*.
- NIST CAVP block-cipher and block-cipher-mode test-vector resources. NIST explicitly states
  that use of these vectors does not replace CAVP validation.
- RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols*, including the AEAD example used by
  the automated tests.
- `cryptography` project documentation for AES, AESGCM, ChaCha20Poly1305, XTS, and the
  legacy CFB/OFB namespace migration.
- NIST FIPS 180-4, *Secure Hash Standard*, for SHA-256.
- NIST FIPS 202, *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*,
  for SHA3-256.
- NIST FIPS 198-1, *The Keyed-Hash Message Authentication Code (HMAC)*.
- RFC 4231, *Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
  HMAC-SHA-384, and HMAC-SHA-512*.
- RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
- Python standard-library documentation for `hashlib` and `hmac`, including
  `hmac.compare_digest`.
- `cryptography` project documentation for `HKDF` and `HKDFExpand`.
- RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2*, for RSA primitives,
  RSAES-OAEP, RSASSA-PSS, MGF1, key representations, and message-length bounds.
- NIST SP 800-56B Revision 2, *Recommendation for Pair-Wise Key-Establishment Using Integer
  Factorization Cryptography*, for RSA-based key-establishment context.
- `cryptography` project documentation for RSA key generation, OAEP, PSS, and key
  serialization.

Published vectors provide reproducible interoperability checks. They are not certification,
formal verification, or an independent audit.

## Diffie-Hellman and key agreement

- Whitfield Diffie and Martin E. Hellman, “New Directions in Cryptography,” *IEEE
  Transactions on Information Theory*, vol. 22, no. 6, 1976.
- Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone, *Handbook of Applied
  Cryptography*, Chapter 12: Key Establishment Protocols and Chapter 3: Number-Theoretic
  Reference Problems.
- RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, for the
  extract-and-expand step applied to the educational shared secret.

## Elliptic curves and modern curve primitives

- Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone, *Handbook of Applied
  Cryptography*, Chapter 6 for elliptic-curve arithmetic and the elliptic-curve discrete
  logarithm problem.
- RFC 7748, *Elliptic Curves for Security*, for X25519 encodings, the bilateral key-exchange
  vector, the all-zero shared-secret check, and the requirement to apply a key-derivation
  function in protocol context.
- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, for Ed25519 key and
  signature sizes and published signature vectors.
- `cryptography` project documentation for X25519 and Ed25519 key generation, exchange,
  signing, verification, and serialization.

The educational curves in CryptoLab are independent teaching examples. RFC vectors validate
library interoperability; they do not certify CryptoLab or establish production readiness.

## Validation, packaging, and mandatory release cross-validation

- SageMath documentation for integer rings, modular rings, CRT, multiplicative order, and
  elliptic curves used by the mandatory independent release cross-validation script.
- Python Packaging User Guide and PEP 639 for package metadata, source distributions,
  wheels, and license metadata.
- Citation File Format 1.2.0 for `CITATION.cff` metadata.
- GitHub Actions and uv documentation for reproducible CI setup and locked dependency
  synchronization.

These tools validate reproducibility and packaging behavior. They do not certify the
cryptographic security of CryptoLab.
