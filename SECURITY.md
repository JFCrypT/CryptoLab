# Security Policy

## Project status

CryptoLab is an educational applied-cryptography laboratory. It is not a production
cryptographic library, a security product, a key-management system, or a replacement for
established cryptographic software.

## Supported release

| Version | Supported |
|---|---|
| 1.1.x | Yes, after the `v1.1.0` public release tag |
| 1.0.x | Superseded by 1.1.x |
| Development history before `v1.0.0` | No public release support |

## Security limitations

Educational implementations may expose intermediate values, branch on secret-dependent
data, use small parameters, and prioritize transparency over constant-time execution. They
must not be used to protect sensitive information.

Library-backed modules reduce implementation risk by delegating modern primitives to an
established library, but CryptoLab still does not claim certification, independent auditing,
formal verification, complete side-channel resistance, or universal production readiness.

Standardized post-quantum operations in 1.1.0 are delegated to OpenSSL 3.5+ EVP. The
post-quantum label describes the design goal and standards family; it is not a certification of
the local OpenSSL build, the host platform, key custody, or any larger protocol.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that may affect users or expose sensitive
information. Report it privately through GitHub's private vulnerability reporting feature
when available.

A useful report includes:

- affected command, module, version, and commit;
- expected and observed behavior;
- reproduction steps using project-generated or non-sensitive data;
- security impact;
- suggested mitigation, if known.

Do not test CryptoLab against systems, data, keys, or services that you do not own or have
explicit authorization to assess.
