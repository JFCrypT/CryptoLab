"""Library-backed X25519 key agreement and Ed25519 digital signatures."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from cryptolab.exceptions import InputValidationError
from cryptolab.hashing.hkdf_sha256 import HKDFResult, derive_hkdf_sha256

CURVE25519_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
DEFAULT_X25519_HKDF_INFO_TEXT = "CryptoLab X25519 key agreement"
DEFAULT_X25519_DERIVED_KEY_BYTES = 32


@dataclass(frozen=True, slots=True)
class CurveKeyPairMaterial:
    """Serialized modern curve key pair and public metadata."""

    algorithm: str
    private_pem: bytes
    public_pem: bytes
    public_key_hex: str
    public_fingerprint_sha256: str
    private_format: str
    public_format: str
    private_encrypted: bool


@dataclass(frozen=True, slots=True)
class X25519ExchangeResult:
    """A local two-party X25519 exchange and HKDF derivation."""

    alice_public_hex: str
    bob_public_hex: str
    alice_shared_secret_hex: str
    bob_shared_secret_hex: str
    shared_secret_matches: bool
    all_zero_shared_secret: bool
    hkdf: HKDFResult
    library: str


@dataclass(frozen=True, slots=True)
class Ed25519SignatureResult:
    """One Ed25519 signature operation."""

    message_hex: str
    signature_hex: str
    public_key_hex: str
    signature_length_bytes: int
    deterministic: bool
    library: str


@dataclass(frozen=True, slots=True)
class Ed25519VerificationResult:
    """Ed25519 verification result."""

    message_hex: str
    signature_hex: str
    public_key_hex: str
    valid: bool


@dataclass(frozen=True, slots=True)
class KeyAgreementProfile:
    """Contextual comparison data for one key-agreement construction."""

    construction: str
    category: str
    mathematical_setting: str
    public_value: str
    shared_secret_processing: str
    authentication: str
    principal_limitation: str


@dataclass(frozen=True, slots=True)
class SignatureProfile:
    """Contextual comparison data for a signature or MAC construction."""

    construction: str
    category: str
    key_relationship: str
    output_size: str
    randomized: str
    verification: str
    principal_limitation: str


def _raw_public_bytes(
    public_key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey,
) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _public_fingerprint(
    public_key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey,
) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der).hexdigest()


def _serialize_key_pair(
    algorithm: str,
    private_key: x25519.X25519PrivateKey | ed25519.Ed25519PrivateKey,
) -> CurveKeyPairMaterial:
    public_key = private_key.public_key()
    return CurveKeyPairMaterial(
        algorithm=algorithm,
        private_pem=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public_pem=public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        public_key_hex=_raw_public_bytes(public_key).hex(),
        public_fingerprint_sha256=_public_fingerprint(public_key),
        private_format="PKCS#8 PEM",
        public_format="SubjectPublicKeyInfo PEM",
        private_encrypted=False,
    )


def generate_x25519_key_pair() -> CurveKeyPairMaterial:
    """Generate and serialize one X25519 key pair."""

    return _serialize_key_pair("X25519", x25519.X25519PrivateKey.generate())


def generate_ed25519_key_pair() -> CurveKeyPairMaterial:
    """Generate and serialize one Ed25519 key pair."""

    return _serialize_key_pair("Ed25519", ed25519.Ed25519PrivateKey.generate())


def load_x25519_private_key(pem: bytes) -> x25519.X25519PrivateKey:
    """Load one unencrypted PKCS#8 PEM X25519 private key."""

    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as error:
        raise InputValidationError(
            "Unable to parse an unencrypted X25519 private-key PEM file."
        ) from error
    if not isinstance(key, x25519.X25519PrivateKey):
        raise InputValidationError("Private-key file does not contain an X25519 private key.")
    return key


def load_x25519_public_key(pem: bytes) -> x25519.X25519PublicKey:
    """Load one SubjectPublicKeyInfo PEM X25519 public key."""

    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as error:
        raise InputValidationError("Unable to parse the X25519 public-key PEM data.") from error
    if not isinstance(key, x25519.X25519PublicKey):
        raise InputValidationError("Public-key file does not contain an X25519 public key.")
    return key


def x25519_private_key_from_raw(data: bytes) -> x25519.X25519PrivateKey:
    """Load one 32-byte raw X25519 private key."""

    if len(data) != CURVE25519_KEY_BYTES:
        raise InputValidationError("X25519 raw private keys must contain exactly 32 bytes.")
    try:
        return x25519.X25519PrivateKey.from_private_bytes(data)
    except ValueError as error:  # pragma: no cover - length is checked first
        raise InputValidationError("Unable to parse the X25519 raw private key.") from error


def x25519_public_key_from_raw(data: bytes) -> x25519.X25519PublicKey:
    """Load one 32-byte raw X25519 public key."""

    if len(data) != CURVE25519_KEY_BYTES:
        raise InputValidationError("X25519 raw public keys must contain exactly 32 bytes.")
    try:
        return x25519.X25519PublicKey.from_public_bytes(data)
    except ValueError as error:  # pragma: no cover - length is checked first
        raise InputValidationError("Unable to parse the X25519 raw public key.") from error


def perform_x25519_exchange(
    *,
    alice_private_key: x25519.X25519PrivateKey,
    bob_private_key: x25519.X25519PrivateKey,
    salt: bytes | None,
    info: bytes,
    derived_key_length: int = DEFAULT_X25519_DERIVED_KEY_BYTES,
) -> X25519ExchangeResult:
    """Compute both sides of a local X25519 exchange and derive one session key."""

    alice_public = alice_private_key.public_key()
    bob_public = bob_private_key.public_key()
    try:
        alice_shared = alice_private_key.exchange(bob_public)
        bob_shared = bob_private_key.exchange(alice_public)
    except ValueError as error:
        raise InputValidationError("X25519 exchange rejected a low-order public value.") from error

    shared_secret_matches = alice_shared == bob_shared
    if not shared_secret_matches:  # pragma: no cover
        raise ArithmeticError("Internal X25519 shared-secret invariant failure.")
    all_zero = not any(alice_shared)
    if all_zero:
        raise InputValidationError("X25519 produced the forbidden all-zero shared secret.")

    hkdf = derive_hkdf_sha256(
        ikm=alice_shared,
        salt=salt,
        info=info,
        length=derived_key_length,
    )
    return X25519ExchangeResult(
        alice_public_hex=_raw_public_bytes(alice_public).hex(),
        bob_public_hex=_raw_public_bytes(bob_public).hex(),
        alice_shared_secret_hex=alice_shared.hex(),
        bob_shared_secret_hex=bob_shared.hex(),
        shared_secret_matches=shared_secret_matches,
        all_zero_shared_secret=all_zero,
        hkdf=hkdf,
        library="cryptography X25519",
    )


def load_ed25519_private_key(pem: bytes) -> ed25519.Ed25519PrivateKey:
    """Load one unencrypted PKCS#8 PEM Ed25519 private key."""

    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as error:
        raise InputValidationError(
            "Unable to parse an unencrypted Ed25519 private-key PEM file."
        ) from error
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise InputValidationError("Private-key file does not contain an Ed25519 private key.")
    return key


def load_ed25519_public_key(pem: bytes) -> ed25519.Ed25519PublicKey:
    """Load one SubjectPublicKeyInfo PEM Ed25519 public key."""

    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as error:
        raise InputValidationError("Unable to parse the Ed25519 public-key PEM data.") from error
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise InputValidationError("Public-key file does not contain an Ed25519 public key.")
    return key


def ed25519_private_key_from_raw(data: bytes) -> ed25519.Ed25519PrivateKey:
    """Load one 32-byte RFC 8032 Ed25519 private seed."""

    if len(data) != CURVE25519_KEY_BYTES:
        raise InputValidationError("Ed25519 raw private keys must contain exactly 32 bytes.")
    try:
        return ed25519.Ed25519PrivateKey.from_private_bytes(data)
    except ValueError as error:  # pragma: no cover - length is checked first
        raise InputValidationError("Unable to parse the Ed25519 raw private key.") from error


def ed25519_public_key_from_raw(data: bytes) -> ed25519.Ed25519PublicKey:
    """Load one 32-byte Ed25519 public key."""

    if len(data) != CURVE25519_KEY_BYTES:
        raise InputValidationError("Ed25519 raw public keys must contain exactly 32 bytes.")
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(data)
    except ValueError as error:  # pragma: no cover - length is checked first
        raise InputValidationError("Unable to parse the Ed25519 raw public key.") from error


def ed25519_sign(
    private_key: ed25519.Ed25519PrivateKey,
    message: bytes,
) -> Ed25519SignatureResult:
    """Sign one message with pure Ed25519."""

    signature = private_key.sign(message)
    public_key_hex = _raw_public_bytes(private_key.public_key()).hex()
    return Ed25519SignatureResult(
        message_hex=message.hex(),
        signature_hex=signature.hex(),
        public_key_hex=public_key_hex,
        signature_length_bytes=len(signature),
        deterministic=True,
        library="cryptography Ed25519",
    )


def ed25519_verify(
    public_key: ed25519.Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> Ed25519VerificationResult:
    """Verify one pure Ed25519 signature."""

    if len(signature) != ED25519_SIGNATURE_BYTES:
        raise InputValidationError("Ed25519 signatures must contain exactly 64 bytes.")
    try:
        public_key.verify(signature, message)
        valid = True
    except InvalidSignature:
        valid = False
    return Ed25519VerificationResult(
        message_hex=message.hex(),
        signature_hex=signature.hex(),
        public_key_hex=_raw_public_bytes(public_key).hex(),
        valid=valid,
    )


def key_agreement_profiles() -> tuple[KeyAgreementProfile, ...]:
    """Compare educational finite-field Diffie-Hellman with X25519."""

    return (
        KeyAgreementProfile(
            construction="Finite-field Diffie-Hellman",
            category="educational in CryptoLab",
            mathematical_setting="Multiplicative subgroup of a small prime field",
            public_value="g^a mod p",
            shared_secret_processing="Fixed-width group element followed by HKDF-SHA-256",  # noqa: S106
            authentication="None by itself",
            principal_limitation="CryptoLab parameters are deliberately tiny and insecure",
        ),
        KeyAgreementProfile(
            construction="X25519",
            category="library-backed",
            mathematical_setting="Montgomery scalar multiplication on Curve25519",
            public_value="32-byte u-coordinate encoding",
            shared_secret_processing="32-byte shared secret followed by HKDF-SHA-256",  # noqa: S106
            authentication="None by itself",
            principal_limitation="Must be embedded in an authenticated protocol",
        ),
    )


def signature_profiles() -> tuple[SignatureProfile, ...]:
    """Compare RSA-PSS, Ed25519, and HMAC-SHA-256 by purpose and trust model."""

    return (
        SignatureProfile(
            construction="RSA-PSS",
            category="digital signature",
            key_relationship="Private signing key; distinct public verification key",
            output_size="Modulus-sized (256 bytes for RSA-2048)",
            randomized="Yes, with a 32-byte salt in CryptoLab",
            verification="Public-key verification",
            principal_limitation=(
                "Larger keys and signatures; parameters must be selected correctly"
            ),
        ),
        SignatureProfile(
            construction="Ed25519",
            category="digital signature",
            key_relationship="32-byte private seed; distinct 32-byte public key",
            output_size="64 bytes",
            randomized="No; pure Ed25519 is deterministic",
            verification="Public-key verification",
            principal_limitation="Does not establish the signer's real-world identity by itself",
        ),
        SignatureProfile(
            construction="HMAC-SHA-256",
            category="symmetric MAC",
            key_relationship="The same secret key is shared by generator and verifier",
            output_size="32 bytes",
            randomized="No",
            verification="Secret-key verification",
            principal_limitation="Any verifier can also generate valid tags; it is not a signature",
        ),
    )
