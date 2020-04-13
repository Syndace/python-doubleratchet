# pylint: disable=too-many-locals
# pylint: disable=too-many-statements

from typing import cast, Set
import warnings

from doubleratchet import (
    DoSProtectionException,
    DuplicateMessageException,
    InconsistentSerializationException,
    SymmetricKeyRatchetSerialized as SKRSerialized
)
from doubleratchet.recommended import (
    diffie_hellman_ratchet_curve25519 as dhr25519,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf
)

from test_recommended_kdfs import generate_unique_random_data

class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_diffie_hellman_ratchet Root Chain info".encode("ASCII")

class MessageChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_diffie_hellman_ratchet Message Chain info".encode("ASCII")

def test_diffie_hellman_ratchet() -> None:
    for impl in [ dhr25519.DiffieHellmanRatchet, dhr448.DiffieHellmanRatchet ]:
        root_chain_key_set: Set[bytes] = set()
        message_chain_constant_set: Set[bytes] = set()
        for _ in range(100):
            # Generate random parameters
            root_chain_key = generate_unique_random_data(32, 32 + 1, root_chain_key_set)
            message_chain_constant = generate_unique_random_data(0, 2 ** 16, message_chain_constant_set)
            bob_key_pair = impl._generate_key_pair() # pylint: disable=protected-access
            bob_pub = bob_key_pair.pub

            # Create instances for Alice and Bob and exchange an initial message
            alice_dhr = impl.create(
                None,
                bob_pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            encryption_key, header = alice_dhr.next_encryption_key()

            bob_dhr = impl.create(
                bob_key_pair,
                header.ratchet_pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert header.pn == 0
            assert header.n  == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            alice_pub = header.ratchet_pub

            # Test that Bob can send to Alice now
            encryption_key, header = bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
            assert header.pn == 0
            assert header.n  == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != bob_pub
            bob_pub = header.ratchet_pub

            # Test that n increases in the header and the ratchet pub stays the same
            encryption_key, header = bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
            assert header.pn == 0
            assert header.n  == 1
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub == bob_pub
            bob_pub = header.ratchet_pub

            # Test that switching sender/receiver triggers a Diffie-Hellman ratchet step
            encryption_key, header = alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert header.pn == 1
            assert header.n  == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != alice_pub
            alice_pub = header.ratchet_pub

            # Test that pn is set correctly in the header
            encryption_key, header = bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
            assert header.pn == 2
            assert header.n  == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub != bob_pub
            bob_pub = header.ratchet_pub

            # Test a few skipped messages (simple case, no Diffie-Hellman ratchet steps)
            skipped_encryption_key_1, skipped_header_1 = bob_dhr.next_encryption_key()
            skipped_encryption_key_2, skipped_header_2 = bob_dhr.next_encryption_key()
            skipped_encryption_key_3, skipped_header_3 = bob_dhr.next_encryption_key()
            encryption_key, header = bob_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
            assert header.pn == 2
            assert header.n  == 4
            assert len(skipped_message_keys) == 3
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert header.ratchet_pub == bob_pub
            bob_pub = header.ratchet_pub

            # Check the skipped message keys
            assert skipped_header_1.ratchet_pub == bob_pub
            assert skipped_header_2.ratchet_pub == bob_pub
            assert skipped_header_3.ratchet_pub == bob_pub
            assert skipped_header_1.pn == 2
            assert skipped_header_2.pn == 2
            assert skipped_header_3.pn == 2
            assert skipped_header_1.n == 1
            assert skipped_header_2.n == 2
            assert skipped_header_3.n == 3
            assert skipped_message_keys[(bob_pub, 1)] == skipped_encryption_key_1
            assert skipped_message_keys[(bob_pub, 2)] == skipped_encryption_key_2
            assert skipped_message_keys[(bob_pub, 3)] == skipped_encryption_key_3

            # Test that attempting to acquire one of these keys again raises an exception
            try:
                alice_dhr.next_decryption_key(skipped_header_3)
                assert False
            except DuplicateMessageException:
                pass

            try:
                alice_dhr.next_decryption_key(header)
                assert False
            except DuplicateMessageException:
                pass

            # Test the more complicated case of skipped message keys (after a Diffie-Hellman ratchet step)
            skipped_encryption_key, skipped_header = bob_dhr.next_encryption_key() # Prepare a message
            encryption_key, header = alice_dhr.next_encryption_key() # Perform a Diffie-Hellman ratchet step
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            encryption_key, header = bob_dhr.next_encryption_key() # Let Alice decrypt a "fresh" message
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            assert len(skipped_message_keys) == 1
            assert (
                skipped_message_keys[(skipped_header.ratchet_pub, skipped_header.n)] == skipped_encryption_key
            )

            # Decrypting this message should not raise an exception but mess up the ratchet instead and return
            # a wrong key:
            decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(skipped_header)
            assert decryption_key != skipped_encryption_key

            # The ratchets are now completely desynchronized, the only option is creating new ratchets. The
            # Double Ratchet mitigates this issue.
            alice_dhr = impl.create(
                None,
                bob_key_pair.pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            encryption_key, header = alice_dhr.next_encryption_key()

            bob_dhr = impl.create(
                bob_key_pair,
                header.ratchet_pub,
                RootChainKDF,
                root_chain_key,
                MessageChainKDF,
                message_chain_constant,
                10
            )
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert header.pn == 0
            assert header.n  == 0
            assert len(skipped_message_keys) == 0
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key
            alice_pub = header.ratchet_pub

            # Test the (hard) DoS protection by skipping more than 10 messages:
            for _ in range(25):
                bob_dhr.next_encryption_key()
            encryption_key, header = bob_dhr.next_encryption_key()
            try:
                alice_dhr.next_decryption_key(header)
                assert False
            except DoSProtectionException:
                pass

            # Perform a Diffie-Hellman ratchet step
            encryption_key, header = alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)

            # Test the (soft) DoS protection:
            encryption_key, header = bob_dhr.next_encryption_key()
            with warnings.catch_warnings(record=True) as w:
                decryption_key, skipped_message_keys = alice_dhr.next_decryption_key(header)
                assert len(w) == 1
                assert issubclass(w[0].category, UserWarning)
                assert "DoS" in str(w[0].message)
            assert len(skipped_message_keys) == 0 # Without DoS protection, this would be 25+
            assert len(encryption_key) == len(decryption_key) == 32
            assert encryption_key == decryption_key

            # Make sure that a root key of a different size than 32 bytes is rejected
            try:
                impl.create(
                    None,
                    bob_key_pair.pub,
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
            encryption_key, header = alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            alice_dhr = impl.deserialize(alice_dhr.serialize(), RootChainKDF, MessageChainKDF,
                                         message_chain_constant, 10)
            encryption_key, header = alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            bob_dhr = impl.deserialize(bob_dhr.serialize(), RootChainKDF, MessageChainKDF,
                                       message_chain_constant, 10)
            encryption_key, header = alice_dhr.next_encryption_key()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key

            # Make sure that a message can be decrypted twice by restoring an old serialized state
            encryption_key, header = alice_dhr.next_encryption_key()
            bob_dhr_serialized = bob_dhr.serialize()
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key
            bob_dhr = impl.deserialize(bob_dhr_serialized, RootChainKDF, MessageChainKDF,
                                       message_chain_constant, 10)
            decryption_key, skipped_message_keys = bob_dhr.next_decryption_key(header)
            assert encryption_key == decryption_key

            # Make sure that removing the sending chain from the serialized data results in an exception:
            cast(SKRSerialized, bob_dhr_serialized["symmetric_key_ratchet"])["schain"] = None
            try:
                impl.deserialize(bob_dhr_serialized, RootChainKDF, MessageChainKDF,
                                 message_chain_constant, 10)
                assert False
            except InconsistentSerializationException:
                pass
