from __future__ import annotations

from cryptolab.labs.dh_man_in_the_middle import run_dh_man_in_the_middle_lab
from cryptolab.public_key.diffie_hellman import perform_dh_exchange


def test_honest_and_attacked_diffie_hellman_workflows() -> None:
    honest = perform_dh_exchange(
        prime=17,
        generator=3,
        alice_private=13,
        bob_private=11,
        info=b"CryptoLab integration",
    )
    assert honest.alice_shared_secret == 6
    assert honest.shared_secret_matches

    attacked = run_dh_man_in_the_middle_lab(
        prime=17,
        generator=3,
        alice_private=13,
        bob_private=11,
        mallory_alice_private=5,
        mallory_bob_private=7,
    )
    assert attacked.honest_shared_secret == honest.alice_shared_secret
    assert attacked.alice_channel_secret != honest.alice_shared_secret
    assert attacked.bob_channel_secret != honest.alice_shared_secret
    assert attacked.alice_channel_matches
    assert attacked.bob_channel_matches
