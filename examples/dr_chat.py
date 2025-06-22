import argparse
import asyncio
import json
import os
import pickle
import shutil
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from doubleratchet import DoubleRatchet as DR, EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)


class DoubleRatchet(DR):
    """
    An example of a Double Ratchet implementation used in the chat.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


class DiffieHellmanRatchet(dhr448.DiffieHellmanRatchet):
    """
    Use the recommended X448-based Diffie-Hellman ratchet implementation in this example.
    """


class AEAD(aead_aes_hmac.AEAD):
    """
    Use the recommended AES/HMAC-based AEAD implementation in this example, with SHA-512 and a fitting info
    string.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat AEAD".encode("ASCII")


class RootChainKDF(kdf_hkdf.KDF):
    """
    Use the recommended HKDF-based KDF implementation for the root chain in this example, with SHA-512 and a
    fitting info string.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat Root Chain KDF".encode("ASCII")


class MessageChainKDF(kdf_separate_hmacs.KDF):
    """
    Use the recommended separate HMAC-based KDF implementation for the message chain in this example, with
    truncated SHA-512.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


# Configuration of the DoubleRatchet class, which has to be passed to each constructing method
# (encrypt_initial_message, decrypt_initial_message, deserialize).
dr_configuration: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 100,
    "max_num_skipped_message_keys": 1000,
    "aead": AEAD
}

# Prepare the associated data, which is application-defined.
ad = "Alice + Bob".encode("ASCII")
shared_secret = "**32 bytes of very secret data**".encode("ASCII")


async def create_double_ratchets(message: bytes) -> Tuple[DoubleRatchet, DoubleRatchet]:
    """
    Create the Double Ratchets for Alice and Bob by encrypting/decrypting an initial message.

    Args:
        message: The initial message.

    Returns:
        The Double Ratchets of Alice and Bob.
    """

    # In a real application, the key exchange that also yields the shared secret for the session initiation
    # probably manages the ratchet key pair.
    bob_ratchet_priv = X448PrivateKey.generate()
    bob_ratchet_pub = bob_ratchet_priv.public_key()

    # Create Alice' Double Ratchet by encrypting the initial message for Bob:
    alice_dr, initial_message_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=bob_ratchet_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        message=message,
        associated_data=ad,
        **dr_configuration
    )
    print(f"Alice> {message.decode('UTF-8')}")

    # Create Bobs' Double Ratchet by decrypting the initial message from Alice:
    bob_dr, initial_message_decrypted = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=bob_ratchet_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial_message_encrypted,
        associated_data=ad,
        **dr_configuration
    )
    print(f"Bob< {initial_message_decrypted.decode('UTF-8')}")

    # Bob should have decrypted the message Alice sent him
    assert message == initial_message_decrypted

    return alice_dr, bob_dr


Deferred = Dict[str, List[EncryptedMessage]]


async def loop(alice_dr: DoubleRatchet, bob_dr: DoubleRatchet, deferred: Deferred) -> bool:
    """
    The loop logic of this chat example.

    Args:
        alice_dr: The Double Ratchet of Alice.
        bob_dr: The Double Ratchet of Bob.
        deferred: The dictionary to hold deferred messages.

    Returns:
        Whether to quit the chat.
    """

    print("a: Send a message from Alice to Bob")
    print("b: Send a message from Bob to Alice")
    print("da: Send a deferred message from Alice to Bob")
    print("db: Send a deferred message from Bob to Alice")
    print("q: Quit")

    action = input("Action: ")

    # (declarations to avoid possibly-used-before-assignment)
    sender: str
    receiver: str
    sender_dr: DoubleRatchet
    receiver_dr: DoubleRatchet

    if action == "a":
        sender = "Alice"
        receiver = "Bob"
        sender_dr = alice_dr
        receiver_dr = bob_dr

    if action == "b":
        sender = "Bob"
        receiver = "Alice"
        sender_dr = bob_dr
        receiver_dr = alice_dr

    if action in [ "a", "b" ]:
        # Ask for the message to send
        message = input(f"{sender}> ")

        # Encrypt the message for the receiver
        message_encrypted = await sender_dr.encrypt_message(message.encode("UTF-8"), ad)

        while True:
            send_or_defer = input("Send the message or save it for later? (s or d): ")
            if send_or_defer in ["s", "d"]:
                break

        if send_or_defer == "s":
            # Now the receiver can decrypt the message
            message_decrypted = await receiver_dr.decrypt_message(message_encrypted, ad)

            print(f"{receiver}< {message_decrypted.decode('UTF-8')}")

        if send_or_defer == "d":
            deferred[sender].append(message_encrypted)
            print("(message saved)")

    if action == "da":
        sender = "Alice"
        receiver = "Bob"
        receiver_dr = bob_dr

    if action == "db":
        sender = "Bob"
        receiver = "Alice"
        receiver_dr = alice_dr

    if action in [ "da", "db" ]:
        num_saved_messages = len(deferred[sender])

        if num_saved_messages == 0:
            print(f"No messages saved from {sender} to {receiver}.")
        else:
            while True:
                message_index = int(input(
                    f"{num_saved_messages} messages saved. Index of the message to send: "
                ))

                if 0 <= message_index < num_saved_messages:
                    break

            message_encrypted = deferred[sender][message_index]
            del deferred[sender][message_index]

            # Now the receiver can decrypt the message
            message_decrypted = await receiver_dr.decrypt_message(message_encrypted, ad)

            print(f"{receiver}< {message_decrypted.decode('UTF-8')}")

    return action != "q"


async def main_loop(alice_dr: DoubleRatchet, bob_dr: DoubleRatchet, deferred: Deferred) -> None:
    """
    The main loop of this chat example.

    Args:
        alice_dr: The Double Ratchet of Alice.
        bob_dr: The Double Ratchet of Bob.
        deferred: The dictionary to hold deferred messages.
    """

    while True:
        try:
            if not await loop(alice_dr, bob_dr, deferred):
                break
        except BaseException:  # pylint: disable=broad-except
            print("Exception raised while processing:")
            traceback.print_exc()
            time.sleep(0.5)

        print("")
        print("")


async def main() -> None:
    """
    The entry point for this chat example. Parses command line args, loads cached data, runs the mainloop and
    caches data before quitting.
    """

    parser = argparse.ArgumentParser(description="Double Ratchet Chat")
    parser.add_argument("-i", "--ignore-cache", dest="ignore_cache", action="store_true",
                        help="ignore the cache completely, neither loading data from the cache nor storing"
                             " data into the cache")
    parser.add_argument("-c", "--clear-cache", dest="clear_cache", action="store_true",
                        help="clear the cache and quit")
    args = parser.parse_args()

    storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dr_chat_storage")

    if args.clear_cache:
        shutil.rmtree(storage_dir)
        return

    if not args.ignore_cache:
        try:
            os.mkdir(storage_dir)
        except FileExistsError:
            pass

    alice_dr: Optional[DoubleRatchet] = None
    bob_dr: Optional[DoubleRatchet] = None
    deferred: Optional[Deferred] = None

    if not args.ignore_cache:
        try:
            with open(os.path.join(storage_dir, "alice_dr.json"), "r", encoding="utf-8") as alice_dr_json:
                alice_dr = DoubleRatchet.from_json(json.load(alice_dr_json), **dr_configuration)

            with open(os.path.join(storage_dir, "bob_dr.json"), "r", encoding="utf-8") as bob_dr_json:
                bob_dr = DoubleRatchet.from_json(json.load(bob_dr_json), **dr_configuration)

            with open(os.path.join(storage_dir, "deferred.pickle"), "rb") as deferred_bin:
                deferred = pickle.load(deferred_bin)
        except OSError:
            pass

    if alice_dr is None or bob_dr is None or deferred is None:
        alice_dr, bob_dr = await create_double_ratchets("(initial message)".encode("UTF-8"))
        deferred = { "Alice": [], "Bob": [] }

    await main_loop(alice_dr, bob_dr, deferred)

    if not args.ignore_cache:
        with open(os.path.join(storage_dir, "alice_dr.json"), "w", encoding="utf-8") as alice_dr_json:
            json.dump(alice_dr.json, alice_dr_json)

        with open(os.path.join(storage_dir, "bob_dr.json"), "w", encoding="utf-8") as bob_dr_json:
            json.dump(bob_dr.json, bob_dr_json)

        with open(os.path.join(storage_dir, "deferred.pickle"), "wb") as deferred_bin:
            pickle.dump(deferred, deferred_bin)


if __name__ == "__main__":
    asyncio.run(main())
