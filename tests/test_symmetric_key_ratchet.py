from typing import Set

from doubleratchet import (
    Chain,
    ChainNotAvailableException,
    SymmetricKeyRatchet
)
from doubleratchet.recommended import HashFunction, kdf_hkdf

from .test_recommended_kdfs import generate_unique_random_data


__all__ = [  # pylint: disable=unused-variable
    "test_symmetric_key_ratchet"
]


class KDF(kdf_hkdf.KDF):
    """
    The KDF to use for testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_symmetric_key_ratchet info".encode("ASCII")


def test_symmetric_key_ratchet() -> None:
    """
    Test the symmetric-key ratchet implementation.
    """

    constant_set: Set[bytes] = set()
    key_set: Set[bytes] = set()

    for _ in range(10000):
        constant = generate_unique_random_data(0, 2 ** 16, constant_set)

        skr_a = SymmetricKeyRatchet.create(KDF, constant)
        skr_b = SymmetricKeyRatchet.create(KDF, constant)

        assert skr_a.previous_sending_chain_length is None
        assert skr_b.previous_sending_chain_length is None
        assert skr_a.sending_chain_length is None
        assert skr_b.sending_chain_length is None
        assert skr_a.receiving_chain_length is None
        assert skr_b.receiving_chain_length is None

        key = generate_unique_random_data(32, 32 + 1, key_set)
        skr_a.replace_chain(Chain.SENDING, key)
        skr_b.replace_chain(Chain.RECEIVING, key)

        assert skr_a.previous_sending_chain_length is None
        assert skr_b.previous_sending_chain_length is None
        assert skr_a.sending_chain_length == 0
        assert skr_b.sending_chain_length is None
        assert skr_a.receiving_chain_length is None
        assert skr_b.receiving_chain_length == 0

        try:
            skr_a.next_decryption_key()
            assert False
        except ChainNotAvailableException as e:
            assert "receiving chain" in str(e)
            assert "never initialized" in str(e)

        try:
            skr_b.next_encryption_key()
            assert False
        except ChainNotAvailableException as e:
            assert "sending chain" in str(e)
            assert "never initialized" in str(e)

        assert skr_a.next_encryption_key() == skr_b.next_decryption_key()

        assert skr_a.sending_chain_length == 1
        assert skr_b.receiving_chain_length == 1

        key = generate_unique_random_data(32, 32 + 1, key_set)
        skr_a.replace_chain(Chain.SENDING, key)
        skr_b.replace_chain(Chain.RECEIVING, key)

        key = generate_unique_random_data(32, 32 + 1, key_set)
        skr_a.replace_chain(Chain.RECEIVING, key)
        skr_b.replace_chain(Chain.SENDING, key)

        assert skr_a.next_encryption_key() == skr_b.next_decryption_key()
        assert skr_a.next_encryption_key() == skr_b.next_decryption_key()

        assert skr_b.next_encryption_key() == skr_a.next_decryption_key()

        assert skr_a.previous_sending_chain_length == 1
        assert skr_b.previous_sending_chain_length is None
        assert skr_a.sending_chain_length == 2
        assert skr_b.sending_chain_length == 1
        assert skr_a.receiving_chain_length == 1
        assert skr_b.receiving_chain_length == 2

        assert len(skr_a.next_encryption_key()) == 32
        skr_b.next_decryption_key()

        try:
            skr_a.replace_chain(Chain.SENDING, b"\x00" * 64)
            assert False
        except ValueError as e:
            assert "chain key" in str(e)
            assert "32 bytes" in str(e)

        assert skr_a.next_encryption_key() == skr_b.next_decryption_key()
