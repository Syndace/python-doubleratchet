import base64
import copy
import json
import os
from typing import Set, Dict, Any, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
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

from .test_recommended_kdfs import generate_unique_random_data


__all__ = [  # pylint: disable=unused-variable
    "test_double_ratchet",
    "test_migrations"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio  # pylint: disable=unused-variable


class RootChainKDF(kdf_hkdf.KDF):
    """
    The root chain KDF to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Root Chain KDF info".encode("ASCII")


class MessageChainKDF(kdf_hkdf.KDF):
    """
    The message chain KDF to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet Message Chain KDF info".encode("ASCII")


class AEAD(aead_aes_hmac.AEAD):
    """
    The AEAD to use while testing.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_double_ratchet AEAD info".encode("ASCII")


class DoubleRatchet(DR):
    """
    The Double Ratchet to use while testing.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
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


async def test_double_ratchet() -> None:
    """
    Test the Double Ratchet implementation.
    """

    shared_secret_set: Set[bytes] = set()
    message_set: Set[bytes] = set()
    ad_set: Set[bytes] = set()

    # for _ in range(200):
    for _ in range(10):
        bob_ratchet_priv = X448PrivateKey.generate()
        bob_ratchet_pub = bob_ratchet_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        shared_secret = generate_unique_random_data(32, 32 + 1, shared_secret_set)
        message = generate_unique_random_data(0, 2 ** 16, message_set)
        ad = generate_unique_random_data(0, 2 ** 16, ad_set)  # pylint: disable=invalid-name

        # Test that passing a shared secret which doesn't consist of 32 bytes raises an exception:
        try:
            await DoubleRatchet.encrypt_initial_message(
                shared_secret=b"\x00" * 64,
                recipient_ratchet_pub=bob_ratchet_pub,
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
            await DoubleRatchet.encrypt_initial_message(
                shared_secret=shared_secret,
                recipient_ratchet_pub=bob_ratchet_pub,
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
        alice_dr, encrypted_message = await DoubleRatchet.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=bob_ratchet_pub,
            message=message,
            associated_data=ad,
            **drc
        )
        bob_dr, plaintext = await DoubleRatchet.decrypt_initial_message(
            shared_secret=shared_secret,
            own_ratchet_priv=bob_ratchet_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            message=encrypted_message,
            associated_data=ad,
            **drc
        )

        assert alice_dr.sending_chain_length == 1
        assert alice_dr.receiving_chain_length is None
        assert bob_dr.sending_chain_length == 0
        assert bob_dr.receiving_chain_length == 1
        assert plaintext == message

        # Send a message back and forth
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message

        # Make sure that each ciphertext is different even though the message is always the same:
        encrypted_message_1 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message_1, ad) == message
        encrypted_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message_2, ad) == message
        assert encrypted_message_1.ciphertext != encrypted_message_2.ciphertext

        # Test the first case of skipped messages (without a Diffie-Hellman ratchet step):
        skipped_message_1 = await alice_dr.encrypt_message(message, ad)
        skipped_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test the second case of skipped messages (with Diffie-Hellman ratchet steps):
        skipped_message_1 = await alice_dr.encrypt_message(message, ad)
        skipped_message_2 = await alice_dr.encrypt_message(message, ad)
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        skipped_message_3 = await alice_dr.encrypt_message(message, ad)
        skipped_message_4 = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message_4, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_3, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_2, ad) == message
        assert await bob_dr.decrypt_message(skipped_message_1, ad) == message

        # Test that only the last 15 skipped message keys are kept around:
        skipped_message = await alice_dr.encrypt_message(message, ad)  # Skipped messages: 1
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 8
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 15
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(skipped_message, ad) == message

        skipped_message = await alice_dr.encrypt_message(message, ad)  # Skipped messages: 1
        for _ in range(7):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 8
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        for _ in range(8):
            await alice_dr.encrypt_message(message, ad)  # Skipped messages: 16
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        try:
            await bob_dr.decrypt_message(skipped_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, before a Diffie-Hellman ratchet step. This should throw a
        # DuplicateMessageException and leave the ratchet intact:
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            await bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except DuplicateMessageException:
            pass

        # Test decrypting a message twice, after a Diffie-Hellman ratchet step. The Double Ratchet does not
        # detect this, thus no DuplicateMessageException should be raise, but a generic
        # AuthenticationFailedException:
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        try:
            await bob_dr.decrypt_message(encrypted_message, ad)
            assert False
        except AuthenticationFailedException:
            pass

        # Even after this failure, the ratchets should still work as before:
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await alice_dr.decrypt_message(await bob_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message

        # Test that (de)serialization doesn't damage the instances:
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        alice_dr = DoubleRatchet.from_json(alice_dr.json, **drc)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr.json, **drc)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        skipped_message = await alice_dr.encrypt_message(message, ad)
        assert await bob_dr.decrypt_message(await alice_dr.encrypt_message(message, ad), ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr.json, **drc)
        assert await bob_dr.decrypt_message(skipped_message, ad) == message

        # Test that (de)serialization can be used to decrypt the same message twice:
        encrypted_message = await alice_dr.encrypt_message(message, ad)
        bob_dr_serialized = bob_dr.json
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message
        bob_dr = DoubleRatchet.from_json(bob_dr_serialized, **drc)
        assert await bob_dr.decrypt_message(encrypted_message, ad) == message


MIGRATION_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migration_data")


async def test_migrations() -> None:
    """
    Test serialization format migrations.
    """

    double_ratchet_configuration: Dict[str, Any] = {
        "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
        "root_chain_kdf": RootChainKDF,
        "message_chain_kdf": MessageChainKDF,
        "message_chain_constant": "test_double_ratchet Message Chain constant".encode("ASCII"),
        "dos_protection_threshold": 10,
        "max_num_skipped_message_keys": 15,
        "aead": AEAD
    }

    associated_data = "test_double_ratchet associated data".encode("ASCII")

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-alice-pre-stable.json"), encoding="utf-8") as file:
        alice_dr_serialized = json.load(file)

    with open(os.path.join(MIGRATION_DATA_DIR, "dr-bob-pre-stable.json"), encoding="utf-8") as file:
        bob_dr_serialized = json.load(file)

    with open(os.path.join(MIGRATION_DATA_DIR, "uninitialized-dr-pre-stable.json"), encoding="utf-8") as file:
        uninitialized_dr_serialized = json.load(file)

    with open(
        os.path.join(MIGRATION_DATA_DIR, "alice-skipped-messages-pre-stable.json"),
        encoding="utf-8"
    ) as file:
        alice_skipped_messages_serialized = json.load(file)

    with open(
        os.path.join(MIGRATION_DATA_DIR, "bob-skipped-messages-pre-stable.json"),
        encoding="utf-8"
    ) as file:
        bob_skipped_messages_serialized = json.load(file)

    alice_skipped_messages: List[Tuple[EncryptedMessage, bytes]] = []
    for skipped_message, plaintext in alice_skipped_messages_serialized:
        alice_skipped_messages.append((
            EncryptedMessage(
                header=Header(
                    ratchet_pub=base64.b64decode(skipped_message["header"]["ratchet_pub"].encode("ASCII")),
                    previous_sending_chain_length=skipped_message["header"]["pn"],
                    sending_chain_length=skipped_message["header"]["n"]
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
                    previous_sending_chain_length=skipped_message["header"]["pn"],
                    sending_chain_length=skipped_message["header"]["n"]
                ),
                ciphertext=base64.b64decode(skipped_message["ciphertext"].encode("ASCII"))
            ),
            base64.b64decode(plaintext.encode("ASCII"))
        ))

    # Verify that the uninitialized ratchet data can't be migrated
    try:
        DoubleRatchet.from_json(uninitialized_dr_serialized, **double_ratchet_configuration)
        assert False
    except InconsistentSerializationException:
        pass

    # Migrate the two valid ratchets
    alice_dr = DoubleRatchet.from_json(alice_dr_serialized, **double_ratchet_configuration)
    bob_dr = DoubleRatchet.from_json(bob_dr_serialized, **double_ratchet_configuration)

    # Verify that skipped messages can be correctly decrypted using the restored instances
    for encrypted_message, plaintext in alice_skipped_messages:
        assert await bob_dr.decrypt_message(encrypted_message, associated_data) == plaintext

    for encrypted_message, plaintext in bob_skipped_messages:
        assert await alice_dr.decrypt_message(encrypted_message, associated_data) == plaintext
