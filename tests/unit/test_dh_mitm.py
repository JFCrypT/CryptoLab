from __future__ import annotations

from cryptolab.labs.dh_man_in_the_middle import run_dh_man_in_the_middle_lab
from cryptolab.labs.models import APPROVED_LABS


def test_diffie_hellman_man_in_the_middle_lab() -> None:
    result = run_dh_man_in_the_middle_lab(
        prime=17,
        generator=3,
        alice_private=13,
        bob_private=11,
        mallory_alice_private=5,
        mallory_bob_private=7,
    )
    assert result.alice_public == 12
    assert result.bob_public == 7
    assert result.honest_shared_secret == 6
    assert result.mallory_public_to_alice == 5
    assert result.mallory_public_to_bob == 11
    assert result.alice_channel_secret == 3
    assert result.mallory_alice_secret == 3
    assert result.bob_channel_secret == 12
    assert result.mallory_bob_secret == 12
    assert result.alice_channel_matches
    assert result.bob_channel_matches
    assert result.alice_bob_secrets_differ
    assert result.alice_channel_key_hex == result.mallory_alice_key_hex
    assert result.bob_channel_key_hex == result.mallory_bob_key_hex
    assert result.alice_channel_key_hex != result.bob_channel_key_hex


def test_all_four_approved_laboratories_are_implemented() -> None:
    assert len(APPROVED_LABS) == 4
    assert {lab.status for lab in APPROVED_LABS} == {"implemented"}
