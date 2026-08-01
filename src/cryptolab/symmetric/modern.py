"""Library-backed modern symmetric cryptography operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from cryptolab.exceptions import AuthenticationError, InputValidationError

BITS_PER_BYTE = 8
AES_BLOCK_BYTES = 16
AES_128_KEY_BYTES = 16
AES_256_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
CHACHA20_POLY1305_KEY_BYTES = 32
CHACHA20_POLY1305_KEY_BITS = CHACHA20_POLY1305_KEY_BYTES * BITS_PER_BYTE
XTS_AES_128_KEY_BYTES = 32
XTS_AES_256_KEY_BYTES = 64
XTS_TWEAK_BYTES = 16


def _load_feedback_modes() -> Any:
    """Load CFB/OFB modes across cryptography namespace migrations."""

    try:
        return import_module("cryptography.hazmat.decrepit.ciphers.modes")
    except ModuleNotFoundError:
        return modes


FEEDBACK_MODES = _load_feedback_modes()


class AESMode(StrEnum):
    """AES modes included in CryptoLab 1.0.0."""

    ECB = "ecb"
    CBC = "cbc"
    CFB128 = "cfb-128"
    OFB = "ofb"
    CTR = "ctr"
    GCM = "gcm"
    XTS = "xts"


class PaddingMode(StrEnum):
    """Padding policy for block-aligned confidentiality modes."""

    PKCS7 = "pkcs7"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ModernCipherResult:
    """One applied-library encryption or decryption result."""

    algorithm: str
    operation: str
    mode: str
    key_size_bits: int
    input_hex: str
    output_hex: str
    padding: str
    parameter_name: str | None
    parameter_hex: str | None
    aad_hex: str | None
    tag_hex: str | None
    authenticated: bool
    library: str = "cryptography"


@dataclass(frozen=True, slots=True)
class AESModeProfile:
    """Didactic comparison data for one AES mode."""

    mode: str
    intended_purpose: str
    padding: str
    external_parameter: str
    authentication: str
    error_propagation: str
    parallelization: str
    random_access: str
    reuse_restriction: str
    principal_limitation: str


@dataclass(frozen=True, slots=True)
class AEADProfile:
    """Comparison data for one authenticated-encryption construction."""

    algorithm: str
    key_size: str
    nonce_size: str
    authentication_tag: str
    block_or_stream_behavior: str
    common_strength: str
    principal_misuse_risk: str
    implementation: str


def _validate_aes_key(key: bytes, mode: AESMode) -> int:
    if mode is AESMode.XTS:
        if len(key) not in {XTS_AES_128_KEY_BYTES, XTS_AES_256_KEY_BYTES}:
            raise InputValidationError(
                "AES-XTS key must contain 32 bytes for XTS-AES-128 or 64 bytes for XTS-AES-256."
            )
        half = len(key) // 2
        if key[:half] == key[half:]:
            raise InputValidationError("AES-XTS key halves must not be identical.")
        return half * BITS_PER_BYTE
    if len(key) not in {AES_128_KEY_BYTES, AES_256_KEY_BYTES}:
        raise InputValidationError("AES key must contain exactly 16 or 32 bytes.")
    return len(key) * BITS_PER_BYTE


def _require_exact_length(value: bytes | None, *, label: str, length: int) -> bytes:
    if value is None:
        raise InputValidationError(f"{label} is required.")
    if len(value) != length:
        raise InputValidationError(f"{label} must contain exactly {length} bytes.")
    return value


def _reject_parameter(value: bytes | None, *, label: str, mode: AESMode) -> None:
    if value is not None:
        raise InputValidationError(f"{label} is not used by AES-{mode.value.upper()}.")


def _apply_padding(data: bytes, padding_mode: PaddingMode) -> bytes:
    if padding_mode is PaddingMode.NONE:
        if len(data) % AES_BLOCK_BYTES != 0:
            raise InputValidationError(
                "Input length must be a multiple of 16 bytes when padding is disabled."
            )
        return data
    padder = symmetric_padding.PKCS7(AES_BLOCK_BYTES * BITS_PER_BYTE).padder()
    return padder.update(data) + padder.finalize()


def _remove_padding(data: bytes, padding_mode: PaddingMode) -> bytes:
    if padding_mode is PaddingMode.NONE:
        return data
    unpadder = symmetric_padding.PKCS7(AES_BLOCK_BYTES * BITS_PER_BYTE).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except ValueError as error:
        raise InputValidationError("PKCS#7 padding is invalid.") from error


def _legacy_feedback_mode(name: str, iv: bytes) -> Any:
    """Return CFB/OFB across cryptography namespace migrations."""

    mode_class = getattr(FEEDBACK_MODES, name)
    return mode_class(iv)


def _cipher_mode(
    mode: AESMode,
    *,
    iv: bytes | None,
    counter: bytes | None,
    tweak: bytes | None,
) -> Any:
    if mode is AESMode.ECB:
        _reject_parameter(iv, label="IV", mode=mode)
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        return modes.ECB()  # noqa: S305 - required controlled educational comparison.
    if mode is AESMode.CBC:
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        return modes.CBC(_require_exact_length(iv, label="CBC IV", length=AES_BLOCK_BYTES))
    if mode is AESMode.CFB128:
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        return _legacy_feedback_mode(
            "CFB", _require_exact_length(iv, label="CFB-128 IV", length=AES_BLOCK_BYTES)
        )
    if mode is AESMode.OFB:
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        return _legacy_feedback_mode(
            "OFB", _require_exact_length(iv, label="OFB IV", length=AES_BLOCK_BYTES)
        )
    if mode is AESMode.CTR:
        _reject_parameter(iv, label="IV", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        return modes.CTR(
            _require_exact_length(
                counter,
                label="CTR initial counter block",
                length=AES_BLOCK_BYTES,
            )
        )
    if mode is AESMode.XTS:
        _reject_parameter(iv, label="IV", mode=mode)
        _reject_parameter(counter, label="Counter block", mode=mode)
        return modes.XTS(_require_exact_length(tweak, label="XTS tweak", length=XTS_TWEAK_BYTES))
    raise RuntimeError("GCM uses the dedicated AESGCM one-shot API.")


def _validate_padding(mode: AESMode, padding_mode: PaddingMode) -> None:
    if mode not in {AESMode.ECB, AESMode.CBC} and padding_mode is not PaddingMode.NONE:
        raise InputValidationError(f"AES-{mode.value.upper()} does not use PKCS#7 padding.")


def aes_encrypt(
    *,
    mode: AESMode,
    key: bytes,
    plaintext: bytes,
    padding_mode: PaddingMode = PaddingMode.NONE,
    iv: bytes | None = None,
    counter: bytes | None = None,
    nonce: bytes | None = None,
    tweak: bytes | None = None,
    aad: bytes = b"",
) -> ModernCipherResult:
    """Encrypt data using a library-backed AES construction."""

    key_size = _validate_aes_key(key, mode)
    _validate_padding(mode, padding_mode)

    if mode is AESMode.GCM:
        _reject_parameter(iv, label="IV", mode=mode)
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        gcm_nonce = _require_exact_length(nonce, label="GCM nonce", length=GCM_NONCE_BYTES)
        combined = AESGCM(key).encrypt(gcm_nonce, plaintext, aad)
        ciphertext, tag = combined[:-AEAD_TAG_BYTES], combined[-AEAD_TAG_BYTES:]
        return ModernCipherResult(
            algorithm=f"AES-{key_size}",
            operation="encrypt",
            mode=mode.value,
            key_size_bits=key_size,
            input_hex=plaintext.hex(),
            output_hex=ciphertext.hex(),
            padding=PaddingMode.NONE.value,
            parameter_name="nonce",
            parameter_hex=gcm_nonce.hex(),
            aad_hex=aad.hex(),
            tag_hex=tag.hex(),
            authenticated=True,
        )

    _reject_parameter(nonce, label="Nonce", mode=mode)
    cipher_mode = _cipher_mode(mode, iv=iv, counter=counter, tweak=tweak)
    if mode is AESMode.XTS:
        if len(plaintext) < AES_BLOCK_BYTES:
            raise InputValidationError("AES-XTS data unit must contain at least 16 bytes.")
        padded = plaintext
    elif mode in {AESMode.ECB, AESMode.CBC}:
        padded = _apply_padding(plaintext, padding_mode)
    else:
        padded = plaintext
    encryptor = Cipher(algorithms.AES(key), cipher_mode).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    parameter_name, parameter = _parameter_for_mode(mode, iv=iv, counter=counter, tweak=tweak)
    return ModernCipherResult(
        algorithm=f"AES-{key_size}",
        operation="encrypt",
        mode=mode.value,
        key_size_bits=key_size,
        input_hex=plaintext.hex(),
        output_hex=ciphertext.hex(),
        padding=padding_mode.value,
        parameter_name=parameter_name,
        parameter_hex=None if parameter is None else parameter.hex(),
        aad_hex=None,
        tag_hex=None,
        authenticated=False,
    )


def aes_decrypt(
    *,
    mode: AESMode,
    key: bytes,
    ciphertext: bytes,
    padding_mode: PaddingMode = PaddingMode.NONE,
    iv: bytes | None = None,
    counter: bytes | None = None,
    nonce: bytes | None = None,
    tweak: bytes | None = None,
    aad: bytes = b"",
    tag: bytes | None = None,
) -> ModernCipherResult:
    """Decrypt data using a library-backed AES construction."""

    key_size = _validate_aes_key(key, mode)
    _validate_padding(mode, padding_mode)

    if mode is AESMode.GCM:
        _reject_parameter(iv, label="IV", mode=mode)
        _reject_parameter(counter, label="Counter block", mode=mode)
        _reject_parameter(tweak, label="Tweak", mode=mode)
        gcm_nonce = _require_exact_length(nonce, label="GCM nonce", length=GCM_NONCE_BYTES)
        gcm_tag = _require_exact_length(tag, label="GCM tag", length=AEAD_TAG_BYTES)
        try:
            plaintext = AESGCM(key).decrypt(gcm_nonce, ciphertext + gcm_tag, aad)
        except InvalidTag as error:
            raise AuthenticationError("AES-GCM authentication failed.") from error
        return ModernCipherResult(
            algorithm=f"AES-{key_size}",
            operation="decrypt",
            mode=mode.value,
            key_size_bits=key_size,
            input_hex=ciphertext.hex(),
            output_hex=plaintext.hex(),
            padding=PaddingMode.NONE.value,
            parameter_name="nonce",
            parameter_hex=gcm_nonce.hex(),
            aad_hex=aad.hex(),
            tag_hex=gcm_tag.hex(),
            authenticated=True,
        )

    if tag is not None:
        raise InputValidationError(f"Authentication tag is not used by AES-{mode.value.upper()}.")
    _reject_parameter(nonce, label="Nonce", mode=mode)
    cipher_mode = _cipher_mode(mode, iv=iv, counter=counter, tweak=tweak)
    if mode is AESMode.XTS and len(ciphertext) < AES_BLOCK_BYTES:
        raise InputValidationError("AES-XTS data unit must contain at least 16 bytes.")
    if mode in {AESMode.ECB, AESMode.CBC} and len(ciphertext) % AES_BLOCK_BYTES != 0:
        raise InputValidationError("AES ciphertext length must be a multiple of 16 bytes.")
    decryptor = Cipher(algorithms.AES(key), cipher_mode).decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = (
        _remove_padding(padded_plaintext, padding_mode)
        if mode in {AESMode.ECB, AESMode.CBC}
        else padded_plaintext
    )
    parameter_name, parameter = _parameter_for_mode(mode, iv=iv, counter=counter, tweak=tweak)
    return ModernCipherResult(
        algorithm=f"AES-{key_size}",
        operation="decrypt",
        mode=mode.value,
        key_size_bits=key_size,
        input_hex=ciphertext.hex(),
        output_hex=plaintext.hex(),
        padding=padding_mode.value,
        parameter_name=parameter_name,
        parameter_hex=None if parameter is None else parameter.hex(),
        aad_hex=None,
        tag_hex=None,
        authenticated=False,
    )


def _parameter_for_mode(
    mode: AESMode,
    *,
    iv: bytes | None,
    counter: bytes | None,
    tweak: bytes | None,
) -> tuple[str | None, bytes | None]:
    if mode in {AESMode.CBC, AESMode.CFB128, AESMode.OFB}:
        return "iv", iv
    if mode is AESMode.CTR:
        return "initial-counter-block", counter
    if mode is AESMode.XTS:
        return "tweak", tweak
    return None, None


def chacha20_poly1305_encrypt(
    *,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> ModernCipherResult:
    """Encrypt and authenticate with ChaCha20-Poly1305."""

    if len(key) != CHACHA20_POLY1305_KEY_BYTES:
        raise InputValidationError("ChaCha20-Poly1305 key must contain exactly 32 bytes.")
    if len(nonce) != GCM_NONCE_BYTES:
        raise InputValidationError("ChaCha20-Poly1305 nonce must contain exactly 12 bytes.")
    combined = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-AEAD_TAG_BYTES], combined[-AEAD_TAG_BYTES:]
    return ModernCipherResult(
        algorithm="ChaCha20-Poly1305",
        operation="encrypt",
        mode="aead",
        key_size_bits=CHACHA20_POLY1305_KEY_BITS,
        input_hex=plaintext.hex(),
        output_hex=ciphertext.hex(),
        padding=PaddingMode.NONE.value,
        parameter_name="nonce",
        parameter_hex=nonce.hex(),
        aad_hex=aad.hex(),
        tag_hex=tag.hex(),
        authenticated=True,
    )


def chacha20_poly1305_decrypt(
    *,
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> ModernCipherResult:
    """Authenticate and decrypt with ChaCha20-Poly1305."""

    if len(key) != CHACHA20_POLY1305_KEY_BYTES:
        raise InputValidationError("ChaCha20-Poly1305 key must contain exactly 32 bytes.")
    if len(nonce) != GCM_NONCE_BYTES:
        raise InputValidationError("ChaCha20-Poly1305 nonce must contain exactly 12 bytes.")
    if len(tag) != AEAD_TAG_BYTES:
        raise InputValidationError("ChaCha20-Poly1305 tag must contain exactly 16 bytes.")
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as error:
        raise AuthenticationError("ChaCha20-Poly1305 authentication failed.") from error
    return ModernCipherResult(
        algorithm="ChaCha20-Poly1305",
        operation="decrypt",
        mode="aead",
        key_size_bits=CHACHA20_POLY1305_KEY_BITS,
        input_hex=ciphertext.hex(),
        output_hex=plaintext.hex(),
        padding=PaddingMode.NONE.value,
        parameter_name="nonce",
        parameter_hex=nonce.hex(),
        aad_hex=aad.hex(),
        tag_hex=tag.hex(),
        authenticated=True,
    )


def aes_mode_profiles() -> tuple[AESModeProfile, ...]:
    """Return the required contextual comparison of all included AES modes."""

    return (
        AESModeProfile(
            "ECB",
            "Single-block primitive demonstrations only",
            "Required for partial final blocks",
            "None",
            "None",
            "A corrupted ciphertext block corrupts only its corresponding plaintext block",
            "Encryption and decryption parallelize",
            "Block-level random access",
            "Deterministic under one key",
            "Repeated plaintext blocks reveal repeated ciphertext blocks",
        ),
        AESModeProfile(
            "CBC",
            "Legacy message confidentiality",
            "PKCS#7 for non-aligned messages",
            "Unpredictable 128-bit IV",
            "None",
            "One corrupted block affects two plaintext blocks",
            "Decryption parallelizes; encryption is sequential",
            "No efficient encryption random access",
            "Never reuse a predictable IV with a key",
            "Confidentiality without integrity",
        ),
        AESModeProfile(
            "CFB-128",
            "Legacy stream-like confidentiality",
            "None",
            "Unpredictable 128-bit IV",
            "None",
            "A bit error affects the current segment and a bounded following region",
            "Encryption is sequential",
            "Limited",
            "Use a fresh unpredictable IV with each key",
            "Confidentiality without integrity; retained for didactic coverage",
        ),
        AESModeProfile(
            "OFB",
            "Legacy synchronous stream-like confidentiality",
            "None",
            "Unique 128-bit IV",
            "None",
            "Bit errors do not propagate beyond the corresponding bit",
            "Keystream generation is sequential",
            "Possible after keystream positioning",
            "Never reuse an IV with a key",
            "Loss of synchronization and no integrity",
        ),
        AESModeProfile(
            "CTR",
            "Parallel stream-like confidentiality",
            "None",
            "Unique 128-bit initial counter block",
            "None",
            "Bit errors do not propagate beyond the corresponding bit",
            "Encryption and decryption parallelize",
            "Efficient random access",
            "Never reuse a counter sequence with a key",
            "Counter reuse reveals plaintext relationships; no integrity",
        ),
        AESModeProfile(
            "GCM",
            "Authenticated encryption for messages",
            "None",
            "Unique 96-bit nonce",
            "AEAD tag authenticates ciphertext and AAD",
            "Modified data causes authentication failure",
            "Highly parallelizable",
            "Block-oriented random access is not independently authenticated",
            "Never reuse a nonce with a key",
            "Nonce reuse can catastrophically break confidentiality and authentication",
        ),
        AESModeProfile(
            "XTS",
            "Confidentiality of storage data units",
            "No message padding; ciphertext stealing may handle a partial final block",
            "128-bit tweak and two AES keys",
            "None",
            "Corruption remains localized within the data unit",
            "Data units can be processed independently",
            "Sector/data-unit oriented",
            "A tweak identifies a data-unit position and must be managed consistently",
            "Not a general message mode and provides no authentication",
        ),
    )


def aead_profiles() -> tuple[AEADProfile, ...]:
    """Return a contextual AES-GCM and ChaCha20-Poly1305 comparison."""

    return (
        AEADProfile(
            "AES-GCM",
            "128 or 256 bits in CryptoLab",
            "96 bits",
            "128 bits",
            "AES counter-mode encryption plus polynomial authentication",
            "Often benefits from dedicated AES hardware acceleration",
            "Nonce reuse with one key is catastrophic",
            "cryptography AESGCM",
        ),
        AEADProfile(
            "ChaCha20-Poly1305",
            "256 bits",
            "96 bits",
            "128 bits",
            "Stream-cipher encryption plus one-time polynomial authentication",
            "Often attractive on systems without AES acceleration",
            "Nonce reuse with one key is catastrophic",
            "cryptography ChaCha20Poly1305",
        ),
    )
