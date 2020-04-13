# pylint: disable=too-many-locals
# pylint: disable=too-many-statements

import base64
import copy
import json
import os
from typing import Set, Dict, Any, List, Tuple

from doubleratchet import (
    AuthenticationFailedException,
    DoubleRatchet as DR,
    DuplicateMessageException,
    EncryptedMessage,
    Header,
    InconsistentSerializationException
)
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf
)

from test_recommended_kdfs import generate_unique_random_data

class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Root Chain KDF info".encode("ASCII")

class MessageChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Message Chain KDF info".encode("ASCII")

class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet AEAD info".encode("ASCII")

class DoubleRatchet(DR):
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data + header.ratchet_pub + header.n.to_bytes(8, "big") + header.pn.to_bytes(8, "big")
        )

drc: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": dhr448.DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
    "dos_protection_threshold": 10,
    "max_num_skipped_message_keys": 15,
    "aead": AEAD
}

def test_double_ratchet() -> None:
    shared_secret_set: Set[bytes] = set()
    message_set:       Set[bytes] = set()
    ad_set:            Set[bytes] = set()
    for _ in range(10):
    #for _ in range(200):
        bob_key_pair  = dhr448.DiffieHellmanRatchet._generate_key_pair() # pylint: disable=protected-access
        shared_secret = generate_unique_random_data(32, 32 + 1, shared_secret_set)
        message       = generate_unique_random_data(0, 2 ** 16, message_set)
        ad            = generate_unique_random_data(0, 2 ** 16, ad_set)

        # Test that passing a shared secret which doesn't consist of 32 bytes raises an exception:
        try:
            DoubleRatchet.encrypt_initial_message(
                shared_secret=b"\x00" * 64,
                recipient_ratchet_pub=bob_key_pair.pub,
                message=message,
                associated_data=ad,
                **drc
            )
            assert False
        except ValueError as e:
            assert "shared secret" in str(e)
            assert "32 bytes" in str(e)

        # Test that passing a DoS protection threshold higher than the maximum number of skipped message key
        # raises an exception:
        try:
            drc_copy = copy.copy(drc)
            drc_copy["dos_protection_threshold"] = 20
            DoubleRatchet.encrypt_initial_message(
                shared_secret=shared_secret,
                recipient_ratchet_pub=bob_key_pair.pub,
                message=message,
                associated_data=ad,
                **drc_copy
            )
            assert False
        except ValueError as e:
            assert "dos_protection_threshold" in str(e)
            assert "bigger than" in str(e)
            assert "max_num_skipped_message_keys" in str(e)

        # Encrypt an initial message from Alice to Bob
        alice_dr, encrypted_message = DoubleRatchet.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=bob_key_pair.pub,
            message=message,
            associated_data=ad,
            **drc
        )
        bob_dr, plaintext = DoubleRatchet.decrypt_initial_message(
            shared_secret=shared_secret,
            own_ratchet_key_pair=bob_key_pair,
            message=encrypted_message,
            associated_data=ad,
            **drc
        )

        assert plaintext == message

        # Send a message back and forth
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message

        # Make sure that each ciphertext is different even though the message is always the same:
        encrypted_message_1 = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(encrypted_message_1, ad) == message
        encrypted_message_2 = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(encrypted_message_2, ad) == message
        assert encrypted_message_1.ciphertext != encrypted_message_2.ciphertext

        # Test the first case of skipped messages (without a Diffie-Hellman ratchet step):
        skipped_message_1 = alice_dr.encrypt_message(message, ad)
        skipped_message_2 = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test the second case of skipped messages (with Diffie-Hellman ratchet steps):
        skipped_message_1 = alice_dr.encrypt_message(message, ad)
        skipped_message_2 = alice_dr.encrypt_message(message, ad)
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        skipped_message_3 = alice_dr.encrypt_message(message, ad)
        skipped_message_4 = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(skipped_message_4, ad) == message
        assert bob_dr.decrypt_message(skipped_message_3, ad) == message
        assert bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test that only the last 15 skipped message keys are kept around:
        skipped_message = alice_dr.encrypt_message(message, ad) # Skipped messages: 1
        for _ in range(7):
            alice_dr.encrypt_message(message, ad) # Skipped messages: 8
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(7):
            alice_dr.encrypt_message(message, ad) # Skipped messages: 15
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(skipped_message, ad) == message

        skipped_message = alice_dr.encrypt_message(message, ad) # Skipped messages: 1
        for _ in range(7):
            alice_dr.encrypt_message(message, ad) # Skipped messages: 8
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(8):
            alice_dr.encrypt_message(message, ad) # Skipped messages: 16
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        try:
            bob_dr.decrypt_message(skipped_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, before a Diffie-Hellman ratchet step. This should throw a
        # DuplicateMessageException and leave the ratchet intact:
        encrypted_message = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, after a Diffie-Hellman ratchet step. The Double Ratchet does not
        # detect this, thus no DuplicateMessageException should be raise, but a generic
        # AuthenticationFailedException:
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        encrypted_message = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except AuthenticationFailedException:
            pass

        # Even after this failure, the ratchets should still work as before:
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        assert alice_dr.decrypt_message(bob_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message

        # Test that (de)serialization doesn't damage the instances:
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        alice_dr = DoubleRatchet.deserialize(alice_dr.serialize(), **drc)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.deserialize(bob_dr.serialize(), **drc)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        skipped_message = alice_dr.encrypt_message(message, ad)
        assert bob_dr.decrypt_message(alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.deserialize(bob_dr.serialize(), **drc)
        assert bob_dr.decrypt_message(skipped_message, ad) == message

        # Test that (de)serialization can be used to decrypt the same message twice:
        encrypted_message = alice_dr.encrypt_message(message, ad)
        bob_dr_serialized = bob_dr.serialize()
        assert bob_dr.decrypt_message(encrypted_message, ad) == message
        bob_dr = DoubleRatchet.deserialize(bob_dr_serialized, **drc)
        assert bob_dr.decrypt_message(encrypted_message, ad) == message

MIGRATION_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migration_data")

def test_migrations() -> None:
    class MigrationAEAD(AEAD):
        pass

    class MigrationRootChainKDF(RootChainKDF):
        pass

    class MigrationMessageChainKDF(MessageChainKDF):
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return HashFunction.SHA_512

    class MigrationDoubleRatchet(DoubleRatchet):
        pass

    double_ratchet_configuration: Dict[str, Any] = {
        "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
        "root_chain_kdf": MigrationRootChainKDF,
        "message_chain_kdf": MigrationMessageChainKDF,
        "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
        "dos_protection_threshold": 10,
        "max_num_skipped_message_keys": 15,
        "aead": MigrationAEAD
    }

    ad = "test_double_ratchet associated data".encode("ASCII")

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-alice-pre-stable.json"), "r") as f:
        alice_dr_serialized = json.load(f)

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-bob-pre-stable.json"), "r") as f:
        bob_dr_serialized = json.load(f)

    with open(os.path.join(MIGRATION_DATA_DIR, "uninitialized-dr-pre-stable.json"), "r") as f:
        uninitialized_dr_serialized = json.load(f)

    with open(os.path.join(MIGRATION_DATA_DIR, "alice-skipped-messages-pre-stable.json"), "r") as f:
        alice_skipped_messages_serialized = json.load(f)

    with open(os.path.join(MIGRATION_DATA_DIR, "bob-skipped-messages-pre-stable.json"), "r") as f:
        bob_skipped_messages_serialized = json.load(f)

    alice_skipped_messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in alice_skipped_messages_serialized:
        alice_skipped_messages.append((
            EncryptedMessage(
                header=Header(
                    ratchet_pub=base64.b64decode(skipped_message["header"]["ratchet_pub"].encode("ASCII")),
                    pn=skipped_message["header"]["pn"],
                    n=skipped_message["header"]["n"]
                ),
                ciphertext=base64.b64decode(skipped_message["ciphertext"].encode("ASCII"))
            ),
            base64.b64decode(plaintext.encode("ASCII"))
        ))

    bob_skipped_messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in bob_skipped_messages_serialized:
        bob_skipped_messages.append((
            EncryptedMessage(
                header=Header(
                    ratchet_pub=base64.b64decode(skipped_message["header"]["ratchet_pub"].encode("ASCII")),
                    pn=skipped_message["header"]["pn"],
                    n=skipped_message["header"]["n"]
                ),
                ciphertext=base64.b64decode(skipped_message["ciphertext"].encode("ASCII"))
            ),
            base64.b64decode(plaintext.encode("ASCII"))
        ))

    # Verify that the uninitialized ratchet data can't be migrated
    try:
        MigrationDoubleRatchet.deserialize(uninitialized_dr_serialized, **double_ratchet_configuration)
        assert False
    except InconsistentSerializationException:
        pass

    # Migrate the two valid ratchets
    alice_dr = MigrationDoubleRatchet.deserialize(alice_dr_serialized, **double_ratchet_configuration)
    bob_dr   = MigrationDoubleRatchet.deserialize(bob_dr_serialized,   **double_ratchet_configuration)

    # Verify that skipped messages can be correctly decrypted using the restored instances
    for encrypted_message, plaintext in alice_skipped_messages:
        assert bob_dr.decrypt_message(encrypted_message, ad) == plaintext

    for encrypted_message, plaintext in bob_skipped_messages:
        assert alice_dr.decrypt_message(encrypted_message, ad) == plaintext
