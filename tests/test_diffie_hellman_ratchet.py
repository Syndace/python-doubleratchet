from typing import List, Set, Type
from warnings import catch_warnings

from doubleratchet import (
    DoSProtectionException,
    DuplicateMessageException
)
from doubleratchet.diffie_hellman_ratchet import DiffieHellmanRatchet
from doubleratchet.recommended import (
    diffie_hellman_ratchet_curve25519 as dhr25519,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf
)

from .test_recommended_kdfs import generate_unique_random_data


__all__ = [  # pylint: disable=unused-variable
    "test_diffie_hellman_ratchet"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio  # pylint: disable=unused-variable


class RootChainKDF(kdf_hkdf.KDF):
    """
    The root chain KDF to use for testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_diffie_hellman_ratchet Root Chain info".encode("ASCII")


class MessageChainKDF(kdf_hkdf.KDF):
    """
    The message chain KDF to use for testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_diffie_hellman_ratchet Message Chain info".encode("ASCII")


async def test_diffie_hellman_ratchet() -> None:
    """
    Test the Diffie-Hellman ratchet implementation.
    """
    # pylint: disable=protected-access

    impls: List[Type[DiffieHellmanRatchet]] = [ dhr25519.DiffieHellmanRatchet, dhr448.DiffieHellmanRatchet ]

    for impl in impls:
        root_chain_key_set: Set[bytes] = set()
        message_chain_constant_set: Set[bytes] = set()
        for _ in range(100):
            # Generate random parameters
            root_chain_key = generate_unique_random_data(32, 32 + 1, root_chain_key_set)
            message_chain_constant = generate_unique_random_data(0, 2 ** 16, message_chain_constant_set)

            bob_priv = impl._generate_priv()

            # Create instances for Alice and Bob and exchange an initial message
            alice_dhr = await impl.create(
                None,
                impl._derive_pub(bob_priv),
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            encryption_key, header = await alice_dhr.next_encryption_key()

            bob_dhr = await impl.create(
                bob_priv,
                header.ratchet_pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 0
            assert header.sending_chain_length == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            alice_pub = header.ratchet_pub

            # Test that Bob can send to Alice now
            encryption_key, header = await bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 0
            assert header.sending_chain_length == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != impl._derive_pub(bob_priv)
            bob_pub = header.ratchet_pub

            # Test that n increases in the header and the ratchet pub stays the same
            encryption_key, header = await bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 0
            assert header.sending_chain_length == 1
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub == bob_pub
            bob_pub = header.ratchet_pub

            # Test that switching sender/receiver triggers a Diffie-Hellman ratchet step
            encryption_key, header = await alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 1
            assert header.sending_chain_length == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != alice_pub
            alice_pub = header.ratchet_pub

            # Test that pn is set correctly in the header
            encryption_key, header = await bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 2
            assert header.sending_chain_length == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != bob_pub
            bob_pub = header.ratchet_pub

            # Test a few skipped messages (simple case, no Diffie-Hellman ratchet steps)
            skipped_encryption_key_1, skipped_header_1 = await bob_dhr.next_encryption_key()
            skipped_encryption_key_2, skipped_header_2 = await bob_dhr.next_encryption_key()
            skipped_encryption_key_3, skipped_header_3 = await bob_dhr.next_encryption_key()
            encryption_key, header = await bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 2
            assert header.sending_chain_length == 4
            assert len(skipped_message_keys) == 3
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub == bob_pub
            bob_pub = header.ratchet_pub

            # Check the skipped message keys
            assert skipped_header_1.ratchet_pub == bob_pub
            assert skipped_header_2.ratchet_pub == bob_pub
            assert skipped_header_3.ratchet_pub == bob_pub
            assert skipped_header_1.previous_sending_chain_length == 2
            assert skipped_header_2.previous_sending_chain_length == 2
            assert skipped_header_3.previous_sending_chain_length == 2
            assert skipped_header_1.sending_chain_length == 1
            assert skipped_header_2.sending_chain_length == 2
            assert skipped_header_3.sending_chain_length == 3
            assert skipped_message_keys[(bob_pub, 1)] == skipped_encryption_key_1
            assert skipped_message_keys[(bob_pub, 2)] == skipped_encryption_key_2
            assert skipped_message_keys[(bob_pub, 3)] == skipped_encryption_key_3

            # Test that attempting to acquire one of these keys again raises an exception
            try:
                await alice_dhr.next_decryption_key(skipped_header_3)
                assert False
            except DuplicateMessageException:
                pass

            try:
                await alice_dhr.next_decryption_key(header)
                assert False
            except DuplicateMessageException:
                pass

            # Test the more complicated case of skipped message keys (after a Diffie-Hellman ratchet step)
            skipped_encryption_key, skipped_header = await bob_dhr.next_encryption_key()  # Prepare a message
            encryption_key, header = await alice_dhr.next_encryption_key()  # Perform a DH ratchet step
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            encryption_key, header = await bob_dhr.next_encryption_key()  # Let Alice decrypt a fresh message
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert len(skipped_message_keys) == 1
            skipped_message_keys_key = (skipped_header.ratchet_pub, skipped_header.sending_chain_length)
            assert skipped_message_keys[skipped_message_keys_key] == skipped_encryption_key

            # Decrypting this message should not raise an exception but mess up the ratchet instead and return
            # a wrong key:
            decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(skipped_header)
            assert decryption_key != skipped_encryption_key

            # The ratchets are now completely desynchronized, the only option is creating new ratchets. The
            # Double Ratchet mitigates this issue.
            alice_dhr = await impl.create(
                None,
                impl._derive_pub(bob_priv),
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            encryption_key, header = await alice_dhr.next_encryption_key()

            bob_dhr = await impl.create(
                bob_priv,
                header.ratchet_pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert header.previous_sending_chain_length == 0
            assert header.sending_chain_length == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            alice_pub = header.ratchet_pub

            # Test the (hard) DoS protection by skipping more than 10 messages:
            for _ in range(25):
                await bob_dhr.next_encryption_key()
            encryption_key, header = await bob_dhr.next_encryption_key()
            try:
                await alice_dhr.next_decryption_key(header)
                assert False
            except DoSProtectionException:
                pass

            # Perform a Diffie-Hellman ratchet step
            encryption_key, header = await alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)

            # Test the (soft) DoS protection:
            encryption_key, header = await bob_dhr.next_encryption_key()
            with catch_warnings(record=True) as warnings:
                decryption_key, skipped_message_keys = await alice_dhr.next_decryption_key(header)
                assert len(warnings) == 1
                assert issubclass(warnings[0].category, UserWarning)
                assert "DoS" in str(warnings[0].message)
            assert len(skipped_message_keys) == 0  # Without DoS protection, this would be 25+
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key

            # Make sure that a root key of a different size than 32 bytes is rejected
            try:
                await impl.create(
                    None,
                    impl._derive_pub(bob_priv),
                    RootChainKDF,
                    b"\00" * 64,
                    MessageChainKDF,
                    message_chain_constant,
                    10
                )
                assert False
            except ValueError as e:
                assert "key" in str(e)
                assert "root chain" in str(e)
                assert "32 bytes" in str(e)

            # Test that (de)serializing doesn't influence the functionality
            encryption_key, header = await alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            alice_dhr = impl.from_json(alice_dhr.json, RootChainKDF, MessageChainKDF,
                                       message_chain_constant, 10)
            encryption_key, header = await alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            bob_dhr = impl.from_json(bob_dhr.json, RootChainKDF, MessageChainKDF,
                                     message_chain_constant, 10)
            encryption_key, header = await alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key

            # Make sure that a message can be decrypted twice by restoring an old serialized state
            encryption_key, header = await alice_dhr.next_encryption_key()
            bob_dhr_serialized = bob_dhr.json
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            bob_dhr = impl.from_json(bob_dhr_serialized, RootChainKDF, MessageChainKDF,
                                     message_chain_constant, 10)
            decryption_key, skipped_message_keys = await bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
