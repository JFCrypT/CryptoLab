# RSA construction comparison

The command

```bash
uv run cryptolab --explain public-key rsa compare
```

compares three deliberately distinct constructions.

| Construction | Category | Purpose | Encoding or padding | Randomized |
|---|---|---|---|---|
| Textbook RSA | educational | expose modular arithmetic | none | no |
| RSA-OAEP | library-backed | encrypt or transport a short secret | OAEP, SHA-256, MGF1-SHA-256 | yes |
| RSA-PSS | library-backed | sign and verify messages | PSS, SHA-256, MGF1-SHA-256, 32-byte salt | yes |

## Key direction

| Operation | Input key | Output or check |
|---|---|---|
| OAEP encryption | recipient public key | ciphertext |
| OAEP decryption | recipient private key | plaintext |
| PSS signing | signer private key | signature |
| PSS verification | signer public key | valid or invalid |

## Limits and misuse risks

Textbook RSA is deterministic and algebraically structured. It is never an applied security
choice. RSA-OAEP has a strict message-size bound and belongs in key transport or other short
message contexts. RSA-PSS provides signatures rather than confidentiality.

No construction is universally superior because they solve different problems. Applied RSA
also remains dependent on key generation, key protection, protocol binding, parameter
agreement, and operational controls that are outside CryptoLab's limited scope.
