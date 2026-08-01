# Controlled laboratory: Caesar brute force

## Identifier

`caesar-brute-force`

## Purpose

This laboratory enumerates the complete Caesar key space for a locally supplied ciphertext.
It reuses the public Caesar implementation and does not contain a second cipher.

```bash
uv run cryptolab --explain lab caesar-brute-force KHOOR
```

## Demonstrated failure

The key space contains only one shift per alphabet symbol. An adversary can therefore display
every candidate plaintext immediately. Basic ciphertext-frequency information is shown, but
CryptoLab does not perform automatic language-model ranking.

## Violated assumption

The construction assumes that the shift can remain secret despite a trivially enumerable key
space.

## Mitigation

Use a modern authenticated-encryption construction with an appropriately large key space.
This laboratory operates only on local user input or repository fixtures.
