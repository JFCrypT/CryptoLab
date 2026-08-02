# Applied RSA: OAEP, PSS, and serialization

Applied RSA operations are delegated to the established `cryptography` library. CryptoLab
does not implement RSA-OAEP or RSA-PSS manually.

## Key generation and serialization

CryptoLab accepts applied RSA modulus sizes of 2048, 3072, or 4096 bits and fixes the public
exponent to 65537. Generated keys are serialized as:

- unencrypted PKCS#8 PEM for the private key;
- SubjectPublicKeyInfo PEM for the public key;
- SHA-256 fingerprint of the DER public key for identification.

The private file is created with owner-only permissions (`0600`) and the public file with
`0644`. Existing files are not replaced unless `--overwrite` is supplied.

```bash
uv run cryptolab --explain public-key rsa applied generate \
  --key-size 2048 \
  --private-key-out private.pem \
  --public-key-out public.pem
```

The unencrypted private-key format is included only as a transparent local serialization
demonstration. CryptoLab is not a production key-management system and does not manage
passwords, HSMs, rotation, backup, revocation, or access control.

## RSA-OAEP

CryptoLab fixes these parameters:

- RSAES-OAEP;
- SHA-256 as the OAEP hash;
- MGF1 with SHA-256;
- empty label.

For a modulus of `k` octets and a hash output of `hLen` octets, RFC 8017 limits the message
to:

\[
mLen \le k-2hLen-2.
\]

With a 2048-bit RSA key and SHA-256, the maximum plaintext is 190 bytes. CryptoLab validates
this bound before encryption and requires ciphertext length to equal the RSA modulus length
before decryption.

```bash
uv run cryptolab public-key rsa applied oaep-encrypt \
  --public-key-file public.pem \
  --plaintext-text "session key material"

uv run cryptolab public-key rsa applied oaep-decrypt \
  --private-key-file private.pem \
  --ciphertext-hex <ciphertext>
```

OAEP encryption is randomized: encrypting the same message twice under the same public key
normally yields different ciphertexts.

## RSA-PSS

CryptoLab fixes these signature parameters:

- RSASSA-PSS;
- SHA-256 message hashing;
- MGF1 with SHA-256;
- 32-byte salt.

```bash
uv run cryptolab public-key rsa applied pss-sign \
  --private-key-file private.pem \
  --message-text "CryptoLab"

uv run cryptolab public-key rsa applied pss-verify \
  --public-key-file public.pem \
  --signature-hex <signature> \
  --message-text "CryptoLab"
```

PSS signatures are randomized. Verification failure returns CryptoLab exit code `4`.

## Encryption is not signing

- encryption uses the recipient's public key and the recipient's private key;
- signing uses the signer's private key and the signer's public key;
- encryption targets confidentiality;
- signatures target integrity, origin authentication, and technical evidence associated with
  the signing key;
- a signature does not conceal the message;
- an RSA ciphertext is not a signature.

## Hybrid encryption

RSA-OAEP is limited to short inputs and should not be used to encrypt a large file block by
block. A hybrid design instead:

1. generates a random symmetric session key;
2. encrypts the data with an AEAD construction such as AES-GCM or ChaCha20-Poly1305;
3. transports the short session key with RSA-OAEP;
4. transmits the RSA ciphertext, AEAD nonce, ciphertext, tag, and any protocol metadata.

CryptoLab explains this composition but does not implement a complete hybrid file format or
key-management protocol in version 1.0.0.

## Failure handling

Malformed keys and invalid parameter lengths are input errors. OAEP decoding failure and
PSS verification failure return code `4` without exposing detailed decoder state. Passing
vectors and round trips demonstrate reproducibility, not certification or side-channel
resistance.
