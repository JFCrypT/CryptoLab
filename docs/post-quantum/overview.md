# Post-quantum cryptography

CryptoLab 1.1.0 adds a bounded post-quantum cryptography layer centered on the three NIST
FIPS standards that are final and directly relevant to general-purpose key establishment and
digital signatures:

- **ML-KEM**, standardized in **FIPS 203**, for key encapsulation;
- **ML-DSA**, standardized in **FIPS 204**, for digital signatures;
- **SLH-DSA**, standardized in **FIPS 205**, for stateless hash-based digital signatures.

The standardized primitives are **library-backed**. CryptoLab does not reimplement their
production cryptographic internals. Operations are delegated to the OpenSSL 3.5+ EVP
provider and CryptoLab adds strict input handling, parameter metadata, structured output,
explanations, file handling, comparisons, and validation.

This design preserves the project boundary: transparent educational code is used where it
helps explain mathematics, while modern standardized primitives are delegated to an
established cryptographic library.

## Backend requirement

The normal CryptoLab installation still requires Python 3.12 or newer and the existing
Python dependencies. Only the standardized `post-quantum` commands additionally require an
**OpenSSL 3.5 or newer** executable that exposes ML-KEM, ML-DSA, and SLH-DSA through EVP.

From a source checkout, `./scripts/install.sh` handles this requirement automatically. When
the operating-system OpenSSL is too old, CryptoLab installs an isolated OpenSSL 3.5 LTS
build below `~/.local/share/cryptolab/openssl/`; `/usr/bin/openssl` and system libraries are
left unchanged. CryptoLab discovers the user-local backend automatically.

Inspect the selected backend with:

```bash
uv run cryptolab --explain post-quantum backend
```

`CRYPTOLAB_OPENSSL` remains available as an explicit advanced override. See
[Isolated OpenSSL PQC backend](backend.md) for the complete installation and discovery
model.

Existing 1.0.0 capabilities do not depend on OpenSSL 3.5 merely because PQC support exists.
The extra requirement applies to standardized PQC operations only.

## Educational foundations

CryptoLab includes two intentionally small educational calculations:

```bash
uv run cryptolab --explain post-quantum foundations ring-multiply \
  17 "1,2" "3,4"

uv run cryptolab --explain post-quantum foundations lwe-example \
  17 \
  --row "1,2" \
  --row "3,4" \
  --secret "5,6" \
  --error "1,-1"
```

The first performs negacyclic multiplication in a tiny ring
`Z_q[x]/(x^n + 1)`. The second computes the pedagogical relation
`b = A*s + e mod q` for a tiny LWE-style sample. Neither command implements ML-KEM,
ML-DSA, a secure LWE distribution, or a lattice cryptosystem.

## Standardized operations

### ML-KEM

```bash
uv run cryptolab post-quantum ml-kem parameters

uv run cryptolab post-quantum ml-kem generate ML-KEM-768 \
  --private-key-out ml-kem-private.pem \
  --public-key-out ml-kem-public.pem

uv run cryptolab --explain post-quantum ml-kem encapsulate ML-KEM-768 \
  --public-key-file ml-kem-public.pem \
  --ciphertext-out ml-kem-ciphertext.bin \
  --shared-secret-out alice-secret.bin

uv run cryptolab --explain post-quantum ml-kem decapsulate ML-KEM-768 \
  --private-key-file ml-kem-private.pem \
  --ciphertext-file ml-kem-ciphertext.bin \
  --shared-secret-out bob-secret.bin
```

ML-KEM creates shared key material. It is a KEM and is not an API for encrypting arbitrary
application messages.

### ML-DSA

```bash
uv run cryptolab post-quantum ml-dsa parameters

uv run cryptolab post-quantum ml-dsa generate ML-DSA-65 \
  --private-key-out ml-dsa-private.pem \
  --public-key-out ml-dsa-public.pem

uv run cryptolab post-quantum ml-dsa sign ML-DSA-65 \
  --private-key-file ml-dsa-private.pem \
  --message-text "CryptoLab" \
  --context-text "example" \
  --signature-out ml-dsa.sig

uv run cryptolab post-quantum ml-dsa verify ML-DSA-65 \
  --public-key-file ml-dsa-public.pem \
  --message-text "CryptoLab" \
  --context-text "example" \
  --signature-file ml-dsa.sig
```

### SLH-DSA

```bash
uv run cryptolab post-quantum slh-dsa parameters

uv run cryptolab post-quantum slh-dsa generate SLH-DSA-SHAKE-128s \
  --private-key-out slh-dsa-private.pem \
  --public-key-out slh-dsa-public.pem

uv run cryptolab post-quantum slh-dsa sign SLH-DSA-SHAKE-128s \
  --private-key-file slh-dsa-private.pem \
  --message-text "CryptoLab" \
  --signature-out slh-dsa.sig

uv run cryptolab post-quantum slh-dsa verify SLH-DSA-SHAKE-128s \
  --public-key-file slh-dsa-public.pem \
  --message-text "CryptoLab" \
  --signature-file slh-dsa.sig
```

## Comparisons

The PQC section extends, rather than replaces, the classical public-key material:

```bash
uv run cryptolab --explain post-quantum compare-key-establishment
uv run cryptolab --explain post-quantum compare-signatures
uv run cryptolab --explain post-quantum overview
```

The comparisons distinguish key agreement from key encapsulation, show the classical
quantum-vulnerable assumptions behind finite-field DH, X25519, RSA-PSS, and Ed25519, and
contrast them with the standardized PQC designs.

## Deliberate exclusions

Version 1.1.0 does not add HQC, FN-DSA/Falcon, Classic McEliece, BIKE, FrodoKEM, NTRU,
PQC TLS, PQC X.509, a post-quantum PKI, an OpenSSL provider, lattice cryptanalysis, Shor's
algorithm, Grover's algorithm, or additional attack laboratories. Future additions require a
separate explicit scope decision.
