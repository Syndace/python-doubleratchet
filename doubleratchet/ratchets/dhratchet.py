from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(
        self,
        root_chain,
        encryption_key_pair_class,
        own_key = None,
        other_enc = None
    ):
        super(DHRatchet, self).__init__()

        self.__root_chain = root_chain
        self._EncryptionKeyPair = encryption_key_pair_class

        if own_key:
            self.__key = own_key
        else:
            self.__newRatchetKey()

        self.__wrapOtherEnc(other_enc)

        if self.__other.enc:
            self.__newRootKey("sending")

    def serialize(self):
        return {
            "super" : super(DHRatchet, self).serialize(),
            "key"   : self.__key.serialize(),
            "other" : self.__other.serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(DHRatchet, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        self.__key   = self._EncryptionKeyPair.fromSerialized(serialized["key"])
        self.__other = self._EncryptionKeyPair.fromSerialized(serialized["other"])

        return self

    def step(self, other_enc):
        if self.triggersStep(other_enc):
            self.__wrapOtherEnc(other_enc)
            self.__newRootKey("receiving")
            self.__newRatchetKey()
            self.__newRootKey("sending")

    def __wrapOtherEnc(self, other_enc):
        self.__other = self._EncryptionKeyPair(enc = other_enc)

    def __newRatchetKey(self):
        self.__key = self._EncryptionKeyPair.generate()

    def triggersStep(self, other_enc):
        return other_enc != self.__other.enc

    def __newRootKey(self, chain):
        self._onNewChainKey(
            self.__root_chain.next(self.__key.getSharedSecret(self.__other)),
            chain
        )

    def _onNewChainKey(self, key, chain):
        raise NotImplementedError

    @property
    def enc(self):
        return self.__key.enc

    @property
    def other_enc(self):
        return self.__other.enc
