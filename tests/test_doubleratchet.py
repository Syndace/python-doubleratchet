import base64
import json
import os

import doubleratchet

from nacl.bindings.crypto_scalarmult import crypto_scalarmult

from nacl.public import PrivateKey as Curve25519DecryptionKey
from nacl.public import PublicKey  as Curve25519EncryptionKey

import pytest

class SendReceiveChain(doubleratchet.chains.ConstKDFChain):
    def __init__(self, key = None):
        super(SendReceiveChain, self).__init__(
            doubleratchet.recommended.RootKeyKDF("SHA-512", "RootKeyKDF info string"),
            "const_data".encode("US-ASCII"),
            key
        )

    def serialize(self):
        return {
            "super": super(SendReceiveChain, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(SendReceiveChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

class SymmetricKeyRatchet(doubleratchet.ratchets.SymmetricKeyRatchet):
    def __init__(self):
        super(SymmetricKeyRatchet, self).__init__(
            SendReceiveChain,
            SendReceiveChain
        )

    def serialize(self):
        return {
            "super": super(SymmetricKeyRatchet, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(SymmetricKeyRatchet, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

class RootChain(doubleratchet.chains.KDFChain):
    def __init__(self):
        super(RootChain, self).__init__(
            doubleratchet.recommended.RootKeyKDF("SHA-512", "IAmARootChain"),
            "I am a root key!".encode("US-ASCII")
        )

    def serialize(self):
        return {
            "super": super(RootChain, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(RootChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

class EncryptionKeyPair(doubleratchet.EncryptionKeyPair):
    def __init__(self, enc = None, dec = None):
        wrap = self.__class__.__wrap

        self.__enc = wrap(enc, Curve25519EncryptionKey)
        self.__dec = wrap(dec, Curve25519DecryptionKey)

        if self.__dec and not self.__enc:
            self.__enc = self.__dec.public_key

    @staticmethod
    def __wrap(key, cls):
        if key == None:
            return None

        if isinstance(key, cls):
            return key

        return cls(key)

    def serialize(self):
        enc = self.enc
        enc = None if enc == None else base64.b64encode(bytes(enc)).decode("US-ASCII")

        dec = self.dec
        dec = None if dec == None else base64.b64encode(bytes(dec)).decode("US-ASCII")

        return {
            "super" : super(EncryptionKeyPair, self).serialize(),
            "enc"   : enc,
            "dec"   : dec
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(EncryptionKeyPair, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        if serialized["enc"] != None:
            self.__enc = cls.__wrap(
                base64.b64decode(serialized["enc"].encode("US-ASCII")),
                Curve25519EncryptionKey
            )

        if serialized["dec"] != None:
            self.__dec = cls.__wrap(
                base64.b64decode(serialized["dec"].encode("US-ASCII")),
                Curve25519DecryptionKey
            )

        return self

    @classmethod
    def generate(cls):
        return cls(dec = Curve25519DecryptionKey.generate())

    @property
    def enc(self):
        return None if self.__enc == None else bytes(self.__enc)

    @property
    def dec(self):
        return None if self.__dec == None else bytes(self.__dec)

    def getSharedSecret(self, other):
        if not self.__dec:
            raise MissingKeyException(
                "Cannot get a shared secret using this EncryptionKeyPairCurve25519, " +
                "decryption key missing."
            )

        if not other.__enc:
            raise MissingKeyException(
                "Cannot get a shared secret using the other " +
                "EncryptionKeyPairCurve25519, encryption key missing"
            )

        return crypto_scalarmult(
            self.dec,
            other.enc
        )

class DR(doubleratchet.ratchets.DoubleRatchet):
    def __init__(self, own_key = None, other_enc = None, skr = None, root_chain = None):
        if skr == None:
            self.__skr = SymmetricKeyRatchet()
        else:
            self.__skr = skr

        if root_chain == None:
            self.__root_chain = RootChain()
        else:
            self.__root_chain = root_chain

        super(DR, self).__init__(
            self.__skr,
            doubleratchet.recommended.CBCHMACAEAD(
                "SHA-512",
                "ExampleCBCHMACAEADConfig"
            ),
            "some associated data".encode("US-ASCII"),
            5,
            self.__root_chain,
            EncryptionKeyPair,
            own_key,
            other_enc
        )

    def serialize(self):
        return {
            "super"      : super(DR, self).serialize(),
            "skr"        : self.__skr.serialize(),
            "root_chain" : self.__root_chain.serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized):
        return super(DR, cls).fromSerialized(
            serialized["super"],
            skr        = SymmetricKeyRatchet.fromSerialized(serialized["skr"]),
            root_chain = RootChain.fromSerialized(serialized["root_chain"])
        )

    def _makeAD(self, header, ad):
        return ad

def test_messages():
    alice_key = EncryptionKeyPair.generate()
    
    alice_ratchet = DR(own_key   = alice_key)
    bob_ratchet   = DR(other_enc = alice_key.enc)

    for _ in range(100):
        message = os.urandom(100)

        c = bob_ratchet.encryptMessage(message)

        assert alice_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message

        message = os.urandom(100)

        c = alice_ratchet.encryptMessage(message)

        assert bob_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message

def test_not_synced():
    alice_key = EncryptionKeyPair.generate()
    alice_ratchet = DR(own_key = alice_key)

    with pytest.raises(doubleratchet.exceptions.NotInitializedException):
        alice_ratchet.encryptMessage("I will fail!".encode("US-ASCII"))

def test_skipped_message():
    alice_key = EncryptionKeyPair.generate()
    
    alice_ratchet = DR(own_key   = alice_key)
    bob_ratchet   = DR(other_enc = alice_key.enc)

    for _ in range(100):
        message_a = os.urandom(100)
        message_b = os.urandom(100)

        c_a = bob_ratchet.encryptMessage(message_a)
        c_b = bob_ratchet.encryptMessage(message_b)

        assert alice_ratchet.decryptMessage(c_b["ciphertext"], c_b["header"]) == message_b
        assert alice_ratchet.decryptMessage(c_a["ciphertext"], c_a["header"]) == message_a

        message_a = os.urandom(100)
        message_b = os.urandom(100)

        c_a = alice_ratchet.encryptMessage(message_a)
        c_b = alice_ratchet.encryptMessage(message_b)

        assert bob_ratchet.decryptMessage(c_b["ciphertext"], c_b["header"]) == message_b
        assert bob_ratchet.decryptMessage(c_a["ciphertext"], c_a["header"]) == message_a

def test_too_many_skipped_messages():
    alice_key = EncryptionKeyPair.generate()
    
    alice_ratchet = DR(own_key   = alice_key)
    bob_ratchet   = DR(other_enc = alice_key.enc)

    # Skip six messages (five skipped messages are allowed)
    for _ in range(6):
        bob_ratchet.encryptMessage(os.urandom(100))

    # Encrypt a seventh message
    c = bob_ratchet.encryptMessage(os.urandom(100))

    with pytest.raises(doubleratchet.exceptions.TooManySavedMessageKeysException):
        alice_ratchet.decryptMessage(c["ciphertext"], c["header"])

def test_serialization():
    alice_key = EncryptionKeyPair.generate()
    
    alice_ratchet = DR(own_key   = alice_key)
    bob_ratchet   = DR(other_enc = alice_key.enc)

    for _ in range(100):
        message = os.urandom(100)

        c = bob_ratchet.encryptMessage(message)

        assert alice_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message

        message = os.urandom(100)

        c = alice_ratchet.encryptMessage(message)

        assert bob_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message

    alice_ratchet_serialized = json.dumps(alice_ratchet.serialize())
    bob_ratchet_serialized   = json.dumps(bob_ratchet.serialize())

    print(alice_ratchet_serialized)
    print(bob_ratchet_serialized)

    alice_ratchet = DR.fromSerialized(json.loads(alice_ratchet_serialized))
    bob_ratchet   = DR.fromSerialized(json.loads(bob_ratchet_serialized))

    for _ in range(100):
        message = os.urandom(100)

        c = bob_ratchet.encryptMessage(message)

        assert alice_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message

        message = os.urandom(100)

        c = alice_ratchet.encryptMessage(message)

        assert bob_ratchet.decryptMessage(c["ciphertext"], c["header"]) == message
