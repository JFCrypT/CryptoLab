from __future__ import annotations

from cryptolab.mathematics.integers import factor_integer, is_prime


def test_factorization_prime_components_are_prime() -> None:
    result = factor_integer(428_759_513)
    assert result.reconstructed == 428_759_513
    assert all(is_prime(item.prime).is_prime for item in result.factors)
