"""Library-backed RSA-OAEP, RSA-PSS, and RSA key serialization."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cryptolab.exceptions import DecryptionError, InputValidationError

RSA_PUBLIC_EXPONENT = 65_537
RSA_ALLOWED_KEY_SIZES = (2048, 3072, 4096)
RSA_OAEP_HASH_BYTES = 32
RSA_PSS_SALT_BYTES = 32


@dataclass(frozen=True, slots=True)
class RSAKeyPairMaterial:
    """Serialized RSA key pair and public metadata."""

    private_pem: bytes
    public_pem: bytes
    key_size_bits: int
    public_exponent: int
    public_fingerprint_sha256: str
    private_format: str
    public_format: str
    private_encrypted: bool


@dataclass(frozen=True, slots=True)
class RSAOAEPResult:
    """One RSA-OAEP encryption or decryption operation."""

    operation: str
    input_hex: str
    output_hex: str
    key_size_bits: int
    maximum_message_bytes: int
    hash_algorithm: str
    mgf: str
    label_hex: str
    randomized: bool
    library: str


@dataclass(frozen=True, slots=True)
class RSAPSSResult:
    """One RSA-PSS signature generation result."""

    message_hex: str
    signature_hex: str
    key_size_bits: int
    hash_algorithm: str
    mgf: str
    salt_length_bytes: int
    randomized: bool
    library: str


@dataclass(frozen=True, slots=True)
class RSAPSSVerificationResult:
    """RSA-PSS verification result."""

    message_hex: str
    signature_hex: str
    key_size_bits: int
    hash_algorithm: str
    salt_length_bytes: int
    valid: bool


@dataclass(frozen=True, slots=True)
class RSAProfile:
    """Contextual comparison data for one RSA construction."""

    construction: str
    category: str
    purpose: str
    encoding_or_padding: str
    randomized: str
    key_operation: str
    principal_limitation: str


def _validate_applied_key_size(key_size: int) -> None:
    if key_size not in RSA_ALLOWED_KEY_SIZES:
        values = ", ".join(str(value) for value in RSA_ALLOWED_KEY_SIZES)
        raise InputValidationError(f"Applied RSA key size must be one of: {values} bits.")


def _public_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der).hexdigest()


def generate_rsa_key_pair(*, key_size: int = 2048) -> RSAKeyPairMaterial:
    """Generate and serialize an applied RSA key pair with public exponent 65537."""

    _validate_applied_key_size(key_size)
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKeyPairMaterial(
        private_pem=private_pem,
        public_pem=public_pem,
        key_size_bits=private_key.key_size,
        public_exponent=RSA_PUBLIC_EXPONENT,
        public_fingerprint_sha256=_public_fingerprint(public_key),
        private_format="PKCS#8 PEM",
        public_format="SubjectPublicKeyInfo PEM",
        private_encrypted=False,
    )


def load_rsa_public_key(pem: bytes) -> rsa.RSAPublicKey:
    """Load one PEM-encoded RSA public key."""

    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as error:
        raise InputValidationError("Unable to parse the RSA public-key PEM data.") from error
    if not isinstance(key, rsa.RSAPublicKey):
        raise InputValidationError("Public-key file does not contain an RSA public key.")
    return key


def load_rsa_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    """Load one unencrypted PEM-encoded RSA private key."""

    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as error:
        raise InputValidationError(
            "Unable to parse an unencrypted RSA private-key PEM file."
        ) from error
    if not isinstance(key, rsa.RSAPrivateKey):
        raise InputValidationError("Private-key file does not contain an RSA private key.")
    return key


def rsa_oaep_maximum_message_bytes(key_size_bits: int) -> int:
    """Return the RFC 8017 RSAES-OAEP message bound for SHA-256."""

    modulus_bytes = (key_size_bits + 7) // 8
    return modulus_bytes - 2 * RSA_OAEP_HASH_BYTES - 2


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_oaep_encrypt(
    public_key: rsa.RSAPublicKey,
    plaintext: bytes,
) -> RSAOAEPResult:
    """Encrypt a bounded message with RSAES-OAEP using SHA-256 and MGF1-SHA-256."""

    maximum = rsa_oaep_maximum_message_bytes(public_key.key_size)
    if len(plaintext) > maximum:
        raise InputValidationError(
            f"RSA-OAEP plaintext must not exceed {maximum} bytes for this key and SHA-256."
        )
    ciphertext = public_key.encrypt(plaintext, _oaep_padding())
    return RSAOAEPResult(
        operation="encrypt",
        input_hex=plaintext.hex(),
        output_hex=ciphertext.hex(),
        key_size_bits=public_key.key_size,
        maximum_message_bytes=maximum,
        hash_algorithm="SHA-256",
        mgf="MGF1-SHA-256",
        label_hex="",
        randomized=True,
        library="cryptography RSA",
    )


def rsa_oaep_decrypt(
    private_key: rsa.RSAPrivateKey,
    ciphertext: bytes,
) -> RSAOAEPResult:
    """Decrypt RSAES-OAEP ciphertext using SHA-256 and MGF1-SHA-256."""

    modulus_bytes = (private_key.key_size + 7) // 8
    if len(ciphertext) != modulus_bytes:
        raise InputValidationError(
            f"RSA-OAEP ciphertext must contain exactly {modulus_bytes} bytes for this key."
        )
    try:
        plaintext = private_key.decrypt(ciphertext, _oaep_padding())
    except ValueError as error:
        raise DecryptionError("RSA-OAEP decryption failed.") from error
    return RSAOAEPResult(
        operation="decrypt",
        input_hex=ciphertext.hex(),
        output_hex=plaintext.hex(),
        key_size_bits=private_key.key_size,
        maximum_message_bytes=rsa_oaep_maximum_message_bytes(private_key.key_size),
        hash_algorithm="SHA-256",
        mgf="MGF1-SHA-256",
        label_hex="",
        randomized=True,
        library="cryptography RSA",
    )


def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=RSA_PSS_SALT_BYTES,
    )


def rsa_pss_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> RSAPSSResult:
    """Sign a message with RSASSA-PSS using SHA-256 and a 32-byte salt."""

    signature = private_key.sign(message, _pss_padding(), hashes.SHA256())
    return RSAPSSResult(
        message_hex=message.hex(),
        signature_hex=signature.hex(),
        key_size_bits=private_key.key_size,
        hash_algorithm="SHA-256",
        mgf="MGF1-SHA-256",
        salt_length_bytes=RSA_PSS_SALT_BYTES,
        randomized=True,
        library="cryptography RSA",
    )


def rsa_pss_verify(
    public_key: rsa.RSAPublicKey,
    message: bytes,
    signature: bytes,
) -> RSAPSSVerificationResult:
    """Verify an RSASSA-PSS signature using the fixed CryptoLab parameters."""

    modulus_bytes = (public_key.key_size + 7) // 8
    if len(signature) != modulus_bytes:
        raise InputValidationError(
            f"RSA-PSS signature must contain exactly {modulus_bytes} bytes for this key."
        )
    try:
        public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
        valid = True
    except InvalidSignature:
        valid = False
    return RSAPSSVerificationResult(
        message_hex=message.hex(),
        signature_hex=signature.hex(),
        key_size_bits=public_key.key_size,
        hash_algorithm="SHA-256",
        salt_length_bytes=RSA_PSS_SALT_BYTES,
        valid=valid,
    )


def rsa_profiles() -> tuple[RSAProfile, ...]:
    """Return the required contextual comparison of educational and applied RSA."""

    return (
        RSAProfile(
            construction="Textbook RSA",
            category="educational",
            purpose="Expose modular arithmetic and key equations",
            encoding_or_padding="None",
            randomized="No",
            key_operation="m^e mod n / c^d mod n",
            principal_limitation="Deterministic and insecure for real data",
        ),
        RSAProfile(
            construction="RSA-OAEP",
            category="library-backed",
            purpose="Encrypt or transport a short secret",
            encoding_or_padding="OAEP with SHA-256 and MGF1-SHA-256",
            randomized="Yes",
            key_operation="Recipient public key encrypts; recipient private key decrypts",
            principal_limitation=(
                "Message length is far below the modulus size; use hybrid encryption"
            ),
        ),
        RSAProfile(
            construction="RSA-PSS",
            category="library-backed",
            purpose="Create and verify digital signatures",
            encoding_or_padding="PSS with SHA-256, MGF1-SHA-256, and 32-byte salt",
            randomized="Yes",
            key_operation="Signer private key signs; signer public key verifies",
            principal_limitation="Provides authenticity, not confidentiality",
        ),
    )
