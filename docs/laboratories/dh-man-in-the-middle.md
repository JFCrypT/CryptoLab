# Diffie-Hellman man-in-the-middle laboratory

This is the fourth and final controlled cryptanalysis laboratory approved for CryptoLab
version 1.0.0.

It demonstrates an active attack against unauthenticated finite-field Diffie-Hellman using
only deliberately small local parameters.

## Honest exchange

With `p = 17`, `g = 3`, Alice private exponent `a = 13`, and Bob private exponent `b = 11`:

```text
A = 12
B = 7
honest shared secret = 6
```

## Public-value substitution

Mallory intercepts `A` and `B`. Instead of forwarding them, Mallory sends one attacker
public value to Alice and a different attacker public value to Bob.

For Mallory exponents `m_A = 5` and `m_B = 7`:

```text
M_A = g^m_A mod p = 5
M_B = g^m_B mod p = 11
```

Alice and Mallory derive the same first channel secret:

```text
M_A^a mod p = A^m_A mod p = 3
```

Bob and Mallory derive the same second channel secret:

```text
M_B^b mod p = B^m_B mod p = 12
```

Alice and Bob no longer share one secret with each other. Mallory knows both channel keys
and can relay, inspect, or alter protected traffic if the surrounding protocol does not
authenticate the exchange.

```bash
uv run cryptolab --explain lab dh-man-in-the-middle \
  17 3 13 11 \
  --mallory-alice-private 5 \
  --mallory-bob-private 7
```

## Violated assumption

The exchanged Diffie-Hellman public values were not authenticated.

## Mitigation

Authenticate the key agreement and its transcript. Examples include signatures or a
properly designed authenticated key-agreement protocol. Merely applying a KDF to the raw
shared secret does not authenticate the peer: Mallory can derive the KDF output for each
attacker-controlled channel.

## Laboratory boundary

The laboratory:

- operates only on user-supplied local teaching values;
- does not use sockets or network services;
- does not target external systems;
- does not implement a reusable interception framework;
- does not add any attack beyond the four explicitly approved laboratories.
