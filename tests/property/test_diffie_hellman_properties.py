from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.public_key.diffie_hellman import perform_dh_exchange

GROUPS = ((17, 3), (23, 5), (29, 2), (31, 3))


@given(
    group=st.sampled_from(GROUPS),
    alice_seed=st.integers(min_value=0, max_value=10_000),
    bob_seed=st.integers(min_value=0, max_value=10_000),
)
def test_diffie_hellman_exchange_is_symmetric(
    group: tuple[int, int],
    alice_seed: int,
    bob_seed: int,
) -> None:
    prime, generator = group
    alice_private = 2 + alice_seed % (prime - 3)
    bob_private = 2 + bob_seed % (prime - 3)
    result = perform_dh_exchange(
        prime=prime,
        generator=generator,
        alice_private=alice_private,
        bob_private=bob_private,
    )
    assert result.alice_shared_secret == result.bob_shared_secret
    assert result.shared_secret_matches
    assert result.hkdf.complete_derivation_matches
