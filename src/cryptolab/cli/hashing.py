"""CLI commands for hashing, HMAC-SHA-256, and HKDF-SHA-256."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.encoding import parse_hex_bytes, read_byte_source
from cryptolab.exceptions import CryptoLabError, InputValidationError, VerificationError
from cryptolab.hashing.hashes import (
    HashAlgorithm,
    avalanche_effect,
    hash_bytes,
    hash_file,
    hash_mac_profiles,
    hash_profiles,
    verify_digest,
)
from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import generate_hmac_sha256, verify_hmac_sha256
from cryptolab.rendering.hashing import (
    AvalancheView,
    DigestVerificationView,
    HashComparisonView,
    HashDigestView,
    HashMACComparisonView,
    HKDFView,
    HMACVerificationView,
    HMACView,
)

if TYPE_CHECKING:
    from cryptolab.encoding import ByteInput
    from cryptolab.hashing.hashes import HashResult
    from cryptolab.rendering.common import SupportsRender

app = typer.Typer(
    name="hashing",
    help="Hash data, authenticate messages, and derive keys with approved initial-scope tools.",
    no_args_is_help=True,
)
hmac_app = typer.Typer(
    name="hmac-sha256",
    help="Generate and verify full-length HMAC-SHA-256 tags.",
    no_args_is_help=True,
)
hkdf_app = typer.Typer(
    name="hkdf-sha256",
    help="Derive key material with transparent HKDF-SHA-256 extract and expand stages.",
    no_args_is_help=True,
)
app.add_typer(hmac_app, name="hmac-sha256")
app.add_typer(hkdf_app, name="hkdf-sha256")


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def _digest_input(
    *,
    algorithm: HashAlgorithm,
    message_text: str | None,
    message_hex: str | None,
    message_file: Path | None,
) -> HashResult:
    selected = sum(value is not None for value in (message_text, message_hex, message_file))
    if selected != 1:
        raise InputValidationError(
            "Select exactly one source for message: --message-text, --message-hex, or "
            "--message-file."
        )
    if message_file is not None:
        return hash_file(message_file, algorithm)
    source = read_byte_source(
        label="message",
        text=message_text,
        hex_value=message_hex,
        file=None,
    )
    return hash_bytes(source.data, algorithm, source_kind=source.source_kind)


def _optional_byte_source(
    *,
    label: str,
    text: str | None,
    hex_value: str | None,
    file: Path | None,
    default: bytes | None,
    default_source: str,
) -> tuple[bytes | None, str]:
    selected = sum(value is not None for value in (text, hex_value, file))
    if selected > 1:
        raise InputValidationError(
            f"Select at most one source for {label}: --{label}-text, --{label}-hex, or "
            f"--{label}-file."
        )
    if selected == 0:
        return default, default_source
    source = read_byte_source(label=label, text=text, hex_value=hex_value, file=file)
    return source.data, source.source_kind


@app.command("digest")
def digest_command(
    context: typer.Context,
    algorithm: Annotated[HashAlgorithm, typer.Argument(help="SHA-256 or SHA3-256.")],
    message_text: Annotated[
        str | None, typer.Option("--message-text", help="Message encoded strictly as UTF-8.")
    ] = None,
    message_hex: Annotated[
        str | None, typer.Option("--message-hex", help="Message canonical hexadecimal bytes.")
    ] = None,
    message_file: Annotated[
        Path | None, typer.Option("--message-file", help="Hash a file incrementally.")
    ] = None,
) -> None:
    """Compute a SHA-256 or SHA3-256 digest."""

    _run(
        context,
        lambda: HashDigestView(
            _digest_input(
                algorithm=algorithm,
                message_text=message_text,
                message_hex=message_hex,
                message_file=message_file,
            )
        ),
    )


@app.command("verify")
def verify_command(
    context: typer.Context,
    algorithm: Annotated[HashAlgorithm, typer.Argument(help="SHA-256 or SHA3-256.")],
    digest_hex: Annotated[
        str, typer.Option("--digest-hex", help="Expected full 32-byte hexadecimal digest.")
    ],
    message_text: Annotated[
        str | None, typer.Option("--message-text", help="Message encoded strictly as UTF-8.")
    ] = None,
    message_hex: Annotated[
        str | None, typer.Option("--message-hex", help="Message canonical hexadecimal bytes.")
    ] = None,
    message_file: Annotated[
        Path | None, typer.Option("--message-file", help="Hash a file incrementally.")
    ] = None,
) -> None:
    """Verify a full SHA-256 or SHA3-256 digest."""

    def factory() -> DigestVerificationView:
        computed = _digest_input(
            algorithm=algorithm,
            message_text=message_text,
            message_hex=message_hex,
            message_file=message_file,
        )
        expected = parse_hex_bytes(digest_hex, label="expected digest")
        result = verify_digest(computed=computed, expected_digest=expected)
        if not result.valid:
            raise VerificationError(f"{algorithm.value} digest verification failed.")
        return DigestVerificationView(result)

    _run(context, factory)


@app.command("avalanche")
def avalanche_command(
    context: typer.Context,
    algorithm: Annotated[HashAlgorithm, typer.Argument(help="SHA-256 or SHA3-256.")],
    left_text: Annotated[str | None, typer.Option("--left-text", help="Left UTF-8 text.")] = None,
    left_hex: Annotated[
        str | None, typer.Option("--left-hex", help="Left canonical hexadecimal bytes.")
    ] = None,
    left_file: Annotated[
        Path | None, typer.Option("--left-file", help="Read left bytes from a file.")
    ] = None,
    right_text: Annotated[
        str | None, typer.Option("--right-text", help="Right UTF-8 text.")
    ] = None,
    right_hex: Annotated[
        str | None, typer.Option("--right-hex", help="Right canonical hexadecimal bytes.")
    ] = None,
    right_file: Annotated[
        Path | None, typer.Option("--right-file", help="Read right bytes from a file.")
    ] = None,
) -> None:
    """Visualize bit changes between two equal-length messages and their digests."""

    def factory() -> AvalancheView:
        left = read_byte_source(label="left", text=left_text, hex_value=left_hex, file=left_file)
        right = read_byte_source(
            label="right", text=right_text, hex_value=right_hex, file=right_file
        )
        return AvalancheView(avalanche_effect(left.data, right.data, algorithm))

    _run(context, factory)


@app.command("compare-hashes")
def compare_hashes_command(context: typer.Context) -> None:
    """Compare SHA-256 and SHA3-256 by family, API, and limitations."""

    _run(context, lambda: HashComparisonView(hash_profiles()))


@app.command("compare-hash-mac")
def compare_hash_mac_command(context: typer.Context) -> None:
    """Distinguish unkeyed hashing from HMAC message authentication."""

    _run(context, lambda: HashMACComparisonView(hash_mac_profiles()))


def _required_source(
    *,
    label: str,
    text: str | None,
    hex_value: str | None,
    file: Path | None,
) -> ByteInput:
    return read_byte_source(label=label, text=text, hex_value=hex_value, file=file)


@hmac_app.command("generate")
def hmac_generate_command(
    context: typer.Context,
    key_text: Annotated[
        str | None, typer.Option("--key-text", help="Key encoded as UTF-8.")
    ] = None,
    key_hex: Annotated[
        str | None, typer.Option("--key-hex", help="Key canonical hexadecimal bytes.")
    ] = None,
    key_file: Annotated[
        Path | None, typer.Option("--key-file", help="Read key bytes from a file.")
    ] = None,
    message_text: Annotated[
        str | None, typer.Option("--message-text", help="Message encoded as UTF-8.")
    ] = None,
    message_hex: Annotated[
        str | None, typer.Option("--message-hex", help="Message canonical hexadecimal bytes.")
    ] = None,
    message_file: Annotated[
        Path | None, typer.Option("--message-file", help="Read message bytes from a file.")
    ] = None,
) -> None:
    """Generate a full-length HMAC-SHA-256 tag."""

    def factory() -> HMACView:
        key = _required_source(label="key", text=key_text, hex_value=key_hex, file=key_file)
        message = _required_source(
            label="message", text=message_text, hex_value=message_hex, file=message_file
        )
        return HMACView(
            generate_hmac_sha256(key.data, message.data),
            key.source_kind,
            message.source_kind,
        )

    _run(context, factory)


@hmac_app.command("verify")
def hmac_verify_command(
    context: typer.Context,
    tag_hex: Annotated[
        str, typer.Option("--tag-hex", help="Expected full 32-byte HMAC-SHA-256 tag.")
    ],
    key_text: Annotated[
        str | None, typer.Option("--key-text", help="Key encoded as UTF-8.")
    ] = None,
    key_hex: Annotated[
        str | None, typer.Option("--key-hex", help="Key canonical hexadecimal bytes.")
    ] = None,
    key_file: Annotated[
        Path | None, typer.Option("--key-file", help="Read key bytes from a file.")
    ] = None,
    message_text: Annotated[
        str | None, typer.Option("--message-text", help="Message encoded as UTF-8.")
    ] = None,
    message_hex: Annotated[
        str | None, typer.Option("--message-hex", help="Message canonical hexadecimal bytes.")
    ] = None,
    message_file: Annotated[
        Path | None, typer.Option("--message-file", help="Read message bytes from a file.")
    ] = None,
) -> None:
    """Verify a full-length HMAC-SHA-256 tag."""

    def factory() -> HMACVerificationView:
        key = _required_source(label="key", text=key_text, hex_value=key_hex, file=key_file)
        message = _required_source(
            label="message", text=message_text, hex_value=message_hex, file=message_file
        )
        tag = parse_hex_bytes(tag_hex, label="HMAC-SHA-256 tag")
        result = verify_hmac_sha256(key.data, message.data, tag)
        if not result.valid:
            raise VerificationError("HMAC-SHA-256 verification failed.")
        return HMACVerificationView(result)

    _run(context, factory)


@hkdf_app.command("derive")
def hkdf_derive_command(
    context: typer.Context,
    length: Annotated[int, typer.Option("--length", help="Desired OKM length in bytes.")],
    ikm_text: Annotated[
        str | None, typer.Option("--ikm-text", help="Input keying material encoded as UTF-8.")
    ] = None,
    ikm_hex: Annotated[
        str | None, typer.Option("--ikm-hex", help="Input keying material hexadecimal bytes.")
    ] = None,
    ikm_file: Annotated[
        Path | None, typer.Option("--ikm-file", help="Read input keying material from a file.")
    ] = None,
    salt_text: Annotated[
        str | None, typer.Option("--salt-text", help="Optional salt encoded as UTF-8.")
    ] = None,
    salt_hex: Annotated[
        str | None, typer.Option("--salt-hex", help="Optional salt hexadecimal bytes.")
    ] = None,
    salt_file: Annotated[
        Path | None, typer.Option("--salt-file", help="Read optional salt from a file.")
    ] = None,
    info_text: Annotated[
        str | None, typer.Option("--info-text", help="Optional context info encoded as UTF-8.")
    ] = None,
    info_hex: Annotated[
        str | None, typer.Option("--info-hex", help="Optional context info hexadecimal bytes.")
    ] = None,
    info_file: Annotated[
        Path | None, typer.Option("--info-file", help="Read optional context info from a file.")
    ] = None,
) -> None:
    """Perform HKDF-SHA-256 extract and expand and expose PRK and OKM."""

    def factory() -> HKDFView:
        ikm = _required_source(label="ikm", text=ikm_text, hex_value=ikm_hex, file=ikm_file)
        salt, salt_source = _optional_byte_source(
            label="salt",
            text=salt_text,
            hex_value=salt_hex,
            file=salt_file,
            default=None,
            default_source="default-zero-salt",
        )
        info, info_source = _optional_byte_source(
            label="info",
            text=info_text,
            hex_value=info_hex,
            file=info_file,
            default=b"",
            default_source="empty",
        )
        if info is None:  # pragma: no cover
            raise RuntimeError("Internal HKDF info invariant failure.")
        return HKDFView(
            derive_hkdf_sha256(ikm=ikm.data, salt=salt, info=info, length=length),
            ikm.source_kind,
            salt_source,
            info_source,
        )

    _run(context, factory)
