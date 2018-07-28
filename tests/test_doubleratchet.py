import os

import doubleratchet

from nacl.bindings.crypto_scalarmult import crypto_scalarmult

from nacl.public import PrivateKey as Curve25519DecryptionKey
from nacl.public import PublicKey  as Curve25519EncryptionKey

import pytest

class SendReceiveChain(doubleratchet.chains.ConstKDFChain):
    def __init__(self, key):
        super(SendReceiveChain, self).__init__(
            key,
            doubleratchet.recommended.RootKeyKDF("SHA-512", "RootKeyKDF info string"),
            "const_data".encode("US-ASCII")
        )

class SymmetricKeyRatchet(doubleratchet.ratchets.SymmetricKeyRatchet):
    def __init__(self):
        super(SymmetricKeyRatchet, self).__init__(
            SendReceiveChain,
            SendReceiveChain
        )

class DoubleRatchetConfig(doubleratchet.DoubleRatchetConfig):
    def __init__(self):
        super(DoubleRatchetConfig, self).__init__(
            SymmetricKeyRatchet(),
            doubleratchet.recommended.CBCHMACAEAD(
                "SHA-512",
                "ExampleCBCHMACAEADConfig"
            ),
            "some associated data".encode("US-ASCII"),
            5
        )

class RootChain(doubleratchet.chains.KDFChain):
    def __init__(self):
        super(RootChain, self).__init__(
            "I am a root key!".encode("US-ASCII"),
            doubleratchet.recommended.RootKeyKDF("SHA-512", "IAmARootChain")
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
        if not key:
            return None

        if isinstance(key, cls):
            return key

        return cls(key)

    @classmethod
    def generate(cls):
        return cls(dec = Curve25519DecryptionKey.generate())

    @property
    def enc(self):
        return bytes(self.__enc) if self.__enc else None

    @property
    def dec(self):
        return bytes(self.__dec) if self.__dec else None

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

class DHRatchetConfig(doubleratchet.DHRatchetConfig):
    def __init__(self, own_key = None, other_enc = None):
        super(DHRatchetConfig, self).__init__(
            RootChain(),
            EncryptionKeyPair,
            own_key,
            other_enc
        )

class Config(doubleratchet.Config):
    def __init__(self, own_key = None, other_enc = None):
        super(Config, self).__init__(
            DoubleRatchetConfig(),
            DHRatchetConfig(own_key, other_enc)
        )

class DR(doubleratchet.ratchets.DoubleRatchet):
    def __init__(self, own_key = None, other_enc = None):
        super(DR, self).__init__(Config(own_key, other_enc))

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
