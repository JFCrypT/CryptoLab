# HMAC-SHA-256

HMAC-SHA-256 combines SHA-256 with a shared secret key to provide message integrity and
symmetric message authentication.

## Generate a tag

```bash
cryptolab hashing hmac-sha256 generate \
  --key-text "shared key" \
  --message-text "authenticated message"
```

Keys and messages support strict UTF-8 text, canonical hexadecimal bytes, or files. CryptoLab
requires a non-empty key, returns the complete 32-byte HMAC-SHA-256 tag, and does not add tag
truncation policy to version 1.0.0.

## Verify a tag

```bash
cryptolab hashing hmac-sha256 verify \
  --key-text "shared key" \
  --message-text "authenticated message" \
  --tag-hex TAG
```

Verification uses `hmac.compare_digest`. A mismatched tag returns exit code `4`; a malformed or
incorrectly sized tag returns exit code `3`.

## Hash versus HMAC

```bash
cryptolab hashing compare-hash-mac
```

A plain hash has no secret key. It provides a deterministic fingerprint but does not prove who
created the message. HMAC requires a shared secret and therefore supports symmetric
authentication.

HMAC is not a digital signature:

- every verifier possesses the shared key;
- every verifier can generate valid tags;
- HMAC does not provide public verification;
- HMAC does not provide technical non-repudiation.

The later signature milestone will compare HMAC with RSA-PSS and Ed25519.

## Validation

The tests include HMAC-SHA-256 cases from RFC 4231. The implementation uses Python's standard
`hmac` module. Vector success is an interoperability check, not certification or an independent
audit.
