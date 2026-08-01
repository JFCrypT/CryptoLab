from __future__ import annotations

import pytest

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.mathematics.algebra import (
    GroupOperation,
    describe_zn,
    element_order,
    generated_subgroup,
    group_generators,
    primitive_roots,
)


def test_describe_prime_and_composite_residue_rings() -> None:
    field = describe_zn(11)
    assert field.is_prime_modulus
    assert field.is_field
    assert field.is_integral_domain
    assert field.nonzero_zero_divisors == ()
    assert field.unit_group_order == 10

    ring = describe_zn(15)
    assert not ring.is_prime_modulus
    assert not ring.is_field
    assert not ring.is_integral_domain
    assert ring.units == (1, 2, 4, 7, 8, 11, 13, 14)
    assert ring.nonzero_zero_divisors == (3, 5, 6, 9, 10, 12)


def test_additive_element_order_and_subgroup() -> None:
    order = element_order(5, 17, GroupOperation.ADDITIVE)
    assert order.order == 17
    assert order.steps[0].value == 0
    assert order.steps[-1].value == 0
    subgroup = generated_subgroup(6, 15, GroupOperation.ADDITIVE)
    assert subgroup.order == 5
    assert subgroup.elements == (0, 6, 12, 3, 9)


def test_multiplicative_element_order_and_subgroup() -> None:
    order = element_order(3, 17, GroupOperation.MULTIPLICATIVE)
    assert order.order == 16
    assert order.ambient_group_order == 16
    subgroup = generated_subgroup(4, 15, GroupOperation.MULTIPLICATIVE)
    assert subgroup.elements == (1, 4)
    assert subgroup.order == 2


def test_nonunit_has_no_multiplicative_group_order() -> None:
    with pytest.raises(MathematicalDomainError, match="only for units"):
        element_order(6, 15, GroupOperation.MULTIPLICATIVE)


def test_additive_and_multiplicative_generators() -> None:
    additive = group_generators(12, GroupOperation.ADDITIVE)
    assert additive.cyclic
    assert additive.generators == (1, 5, 7, 11)

    multiplicative = group_generators(8, GroupOperation.MULTIPLICATIVE)
    assert not multiplicative.cyclic
    assert multiplicative.generators == ()


def test_primitive_roots_modulo_prime() -> None:
    result = primitive_roots(17)
    assert result.cyclic
    assert result.ambient_group_order == 16
    assert result.generators == (3, 5, 6, 7, 10, 11, 12, 14)


def test_primitive_roots_reject_composite_modulus() -> None:
    with pytest.raises(MathematicalDomainError, match="prime modulus"):
        primitive_roots(15)


def test_algebraic_bounds_and_modulus_validation() -> None:
    with pytest.raises(MathematicalDomainError):
        describe_zn(1)
    with pytest.raises(ResourceLimitError):
        describe_zn(4097)
