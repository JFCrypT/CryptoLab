# Vigenère cipher

The repeated-key Vigenère cipher applies a sequence of Caesar-like modular shifts.

For an alphabet of size `m`:

```text
c_i = m_i + k_i mod m
m_i = c_i - k_i mod m
```

The key must be non-empty and every key symbol must belong to the selected alphabet.

## Encrypt and decrypt

```bash
uv run cryptolab classical vigenere encrypt ATTACKATDAWN LEMON
uv run cryptolab classical vigenere decrypt LXFOPVEFRNHR LEMON
```

Use `--explain` to display the message index, repeated-key alignment, key index, and output
index. The alignment can also be requested as a first-class command:

```bash
uv run cryptolab classical vigenere align "ATTACK AT DAWN" LEMON
```

The alignment command exposes the table in human output and structured alignment entries in
JSON output.

## Preserved symbols

Under the default `preserve` policy, an unknown message symbol remains unchanged and does
not consume a key symbol. This convention is explicit and tested because advancing the key
through punctuation would produce a different cipher.

```bash
uv run cryptolab --explain classical vigenere encrypt "ATTACK AT DAWN" LEMON
```

!!! warning
    Repeated-key Vigenère is vulnerable to classical cryptanalysis and is not secure for
    modern use.
