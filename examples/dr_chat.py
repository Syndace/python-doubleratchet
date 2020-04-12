import argparse
import json
import os
import pickle
import shutil
import time
import traceback
from typing import Dict, List, Tuple, Any, Optional

from doubleratchet import double_ratchet
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448,
    kdf_hkdf,
    kdf_separate_hmacs
)
from doubleratchet.recommended.hash_function import HashFunction
from doubleratchet.types import EncryptedMessage, Header

class DoubleRatchet(double_ratchet.DoubleRatchet):
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data + header.ratchet_pub + header.n.to_bytes(8, "big") + header.pn.to_bytes(8, "big")
        )

class DiffieHellmanRatchet(diffie_hellman_ratchet_curve448.DiffieHellmanRatchet):
    pass

class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat AEAD".encode("ASCII")

class RootChainKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat Root Chain KDF".encode("ASCII")

class MessageChainKDF(kdf_separate_hmacs.KDF):
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

def create_double_ratchets(message: bytes) -> Tuple[DoubleRatchet, DoubleRatchet]:
    # Abuse the Curve448 DiffieHellmanRatchet implementation to generate a key pair. In a "real" application,
    # the key exchange that also yields the shared secret for the session initiation probably manages the
    # ratchet key pair.
    bob_ratchet_key_pair = DiffieHellmanRatchet._generate_key_pair() # pylint: disable=protected-access

    # Create Alice' Double Ratchet by encrypting the initial message for Bob:
    alice_dr, initial_message_encrypted = DoubleRatchet.encrypt_initial_message(
        shared_secret         = shared_secret,
        recipient_ratchet_pub = bob_ratchet_key_pair.pub,
        message               = message,
        associated_data       = ad,
        **dr_configuration
    )
    print("Alice> {}".format(message.decode("UTF-8")))

    # Create Bobs' Double Ratchet by decrypting the initial message from Alice:
    bob_dr, initial_message_decrypted = DoubleRatchet.decrypt_initial_message(
        shared_secret        = shared_secret,
        own_ratchet_key_pair = bob_ratchet_key_pair,
        message              = initial_message_encrypted,
        associated_data      = ad,
        **dr_configuration
    )
    print("Bob< {}".format(initial_message_decrypted.decode("UTF-8")))

    # Bob should have decrypted the message Alice sent him
    assert message == initial_message_decrypted

    return alice_dr, bob_dr

Deferred = Dict[str, List[EncryptedMessage]]
def loop(alice_dr: DoubleRatchet, bob_dr: DoubleRatchet, deferred: Deferred) -> bool:
    # pylint: disable=too-many-branches

    print("a: Send a message from Alice to Bob")
    print("b: Send a message from Bob to Alice")
    print("da: Send a deferred message from Alice to Bob")
    print("db: Send a deferred message from Bob to Alice")
    print("q: Quit")

    action = input("Action: ")

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
        message = input("{}> ".format(sender))

        # Encrypt the message for the receiver
        message_encrypted = sender_dr.encrypt_message(message.encode("UTF-8"), ad)

        while True:
            send_or_defer = input("Send the message or save it for later? (s or d): ")
            if send_or_defer in ["s", "d"]:
                break

        if send_or_defer == "s":
            # Now the receiver can decrypt the message
            message_decrypted = receiver_dr.decrypt_message(message_encrypted, ad)

            print("{}< {}".format(receiver, message_decrypted.decode("UTF-8")))

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
            print("No messages saved from {} to {}.".format(sender, receiver))
        else:
            while True:
                message_index = int(input("{} messages saved. Index of the message to send: ".format(
                    num_saved_messages
                )))

                if 0 <= message_index < num_saved_messages:
                    break

            message_encrypted = deferred[sender][message_index]
            del deferred[sender][message_index]

            # Now the receiver can decrypt the message
            message_decrypted = receiver_dr.decrypt_message(message_encrypted, ad)

            print("{}< {}".format(receiver, message_decrypted.decode("UTF-8")))

    return action != "q"

def main_loop(alice_dr: DoubleRatchet, bob_dr: DoubleRatchet, deferred: Deferred) -> None:
    while True:
        try:
            if not loop(alice_dr, bob_dr, deferred):
                break
        except BaseException: # pylint: disable=broad-except
            print("Exception raised while processing:")
            traceback.print_exc()
            time.sleep(0.5)

        print("")
        print("")

def main() -> None:
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

    alice_dr : Optional[DoubleRatchet] = None
    bob_dr   : Optional[DoubleRatchet] = None
    deferred : Optional[Deferred]      = None

    if not args.ignore_cache:
        try:
            with open(os.path.join(storage_dir, "alice_dr.json"), "r") as f:
                alice_dr = DoubleRatchet.deserialize(json.load(f), **dr_configuration)

            with open(os.path.join(storage_dir, "bob_dr.json"), "r") as f:
                bob_dr = DoubleRatchet.deserialize(json.load(f), **dr_configuration)

            with open(os.path.join(storage_dir, "deferred.pickle"), "rb") as f_bin:
                deferred = pickle.load(f_bin)
        except OSError:
            pass

    if alice_dr is None or bob_dr is None or deferred is None:
        alice_dr, bob_dr = create_double_ratchets("(initial message)".encode("UTF-8"))
        deferred = { "Alice": [], "Bob": [] }

    main_loop(alice_dr, bob_dr, deferred)

    if not args.ignore_cache:
        with open(os.path.join(storage_dir, "alice_dr.json"), "w") as f:
            json.dump(alice_dr.serialize(), f)

        with open(os.path.join(storage_dir, "bob_dr.json"), "w") as f:
            json.dump(bob_dr.serialize(), f)

        with open(os.path.join(storage_dir, "deferred.pickle"), "wb") as f_bin:
            pickle.dump(deferred, f_bin)

if __name__ == "__main__":
    main()
