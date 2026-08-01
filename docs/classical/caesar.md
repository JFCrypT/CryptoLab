# Caesar cipher

The Caesar cipher represents each alphabet symbol by an index and applies modular
addition.

For an alphabet of size `m`:

```text
E_k(i) = i + k mod m
D_k(i) = i - k mod m
```

Positive, zero, and negative shifts are accepted. The supplied shift is normalized modulo
the alphabet size and is never silently interpreted as an alphabet-independent value.

## Encrypt and decrypt

```bash
uv run cryptolab classical caesar encrypt PARABOLOIDE 9 --alphabet spanish-upper
uv run cryptolab classical caesar decrypt YJAJKXTXQMN 9 --alphabet spanish-upper
uv run cryptolab classical caesar encrypt HELLO -3
```

Use `--explain` to display the input index, normalized shift, output index, and output symbol
for every character.

## Transformation table

```bash
uv run cryptolab classical caesar table 9 --alphabet spanish-upper
```

The table visualizes the permutation induced by the selected key.

## Exhaustive candidates

```bash
uv run cryptolab classical caesar candidates KHOOR
```

The command enumerates the complete finite key space. It does not automatically declare a
candidate correct and does not use a language model.

## Character frequencies

```bash
uv run cryptolab --explain classical caesar frequency ABRACADABRA
```

Frequency analysis reports counts and percentages for symbols in the selected alphabet.
Unknown symbols are counted separately. Language-specific inference remains outside this
module and will be used only in the approved controlled Caesar laboratory.

!!! warning
    The Caesar cipher is educational and is not secure for modern use.
