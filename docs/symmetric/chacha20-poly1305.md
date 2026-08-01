# ChaCha20-Poly1305

ChaCha20-Poly1305 is the second authenticated-encryption construction in CryptoLab. It is
implemented through `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
CryptoLab does not implement standalone ChaCha20, XChaCha20-Poly1305, or manual Poly1305.

## Parameters

- key: 32 bytes;
- nonce: 12 bytes;
- plaintext or ciphertext;
- optional associated data;
- authentication tag: 16 bytes.

Encryption:

```bash
cryptolab symmetric chacha20-poly1305 encrypt \
  --key-hex 0000000000000000000000000000000000000000000000000000000000000000 \
  --nonce-hex 000000000000000000000000 \
  --plaintext-text "message" \
  --aad-text "header"
```

Decryption receives ciphertext and tag separately:

```bash
cryptolab symmetric chacha20-poly1305 decrypt \
  --key-hex KEY_HEX \
  --nonce-hex NONCE_HEX \
  --ciphertext-hex CIPHERTEXT_HEX \
  --tag-hex TAG_HEX \
  --aad-text "header"
```

Authenticated decryption releases plaintext only after the tag verifies. A different key,
nonce, ciphertext, tag, or AAD causes exit code `4`.

## Security properties and limits

ChaCha20-Poly1305 provides confidentiality and integrity for plaintext while authenticating
optional AAD. The nonce does not need to be secret, but it must not repeat under one key.
Nonce reuse destroys the one-time assumptions of the construction and can reveal plaintext
relationships and authentication material.

The CLI demonstrates correct parameter handling. It is not a protocol, key-management
system, or nonce-allocation service.

## Validation

CryptoLab includes the RFC 8439 authenticated-encryption example, round-trip tests,
invalid-tag tests, input-length checks, and property-based tests.
