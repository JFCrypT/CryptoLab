# Configurable alphabets

Classical ciphers operate on an explicit ordered alphabet. An alphabet is data, not an
interface language.

Each alphabet must contain:

- from 2 to 256 symbols;
- unique symbols;
- exactly one Unicode code point per symbol;
- a stable order used as the modular index mapping.

Built-in alphabets:

- `latin-upper`: `A` through `Z`;
- `spanish-upper`: `A` through `N`, `Ñ`, then `O` through `Z`.

The implementation is case-sensitive and performs no automatic case conversion, accent
removal, or Unicode normalization.

## Custom JSON alphabet

```json
{
  "name": "binary",
  "symbols": ["0", "1"]
}
```

Use it with:

```bash
uv run cryptolab classical caesar encrypt 010 1 --alphabet-file binary.json
```

`--alphabet` and `--alphabet-file` are mutually exclusive. When neither is supplied,
`latin-upper` is used.

## Unknown symbols

The common policy is selected with:

```text
--unknown-symbols preserve|reject
```

The default is `preserve`.

For Caesar, preserved symbols remain unchanged. For Vigenère, a preserved symbol does not
advance the key. Polybius uses an explicit `u+HEX` token so preserved symbols can be
recovered without ambiguity.

The shorter `--unknown` alias is accepted for backward-compatible command use.
