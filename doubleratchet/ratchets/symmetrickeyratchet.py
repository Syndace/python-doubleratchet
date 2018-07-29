from __future__ import absolute_import

from ..exceptions import NotInitializedException
from .ratchet import Ratchet

class SymmetricKeyRatchet(Ratchet):
    def __init__(self, sending_chain_class, receiving_chain_class):
        super(SymmetricKeyRatchet, self).__init__()

        self.__SendingChain   = sending_chain_class
        self.__ReceivingChain = receiving_chain_class

        self.__sending_chain   = None
        self.__receiving_chain = None

        self.__previous_sending_chain_length = None

    def serialize(self):
        sending_chain = self.__sending_chain
        sending_chain = None if sending_chain == None else sending_chain.serialize()

        receiving_chain = self.__receiving_chain
        receiving_chain = None if receiving_chain == None else receiving_chain.serialize()

        return {
            "super"  : super(SymmetricKeyRatchet, self).serialize(),
            "schain" : sending_chain,
            "rchain" : receiving_chain,
            "prev_schain_length" : self.__previous_sending_chain_length
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(SymmetricKeyRatchet, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        if serialized["schain"] != None:
            self.__sending_chain = self.__SendingChain.fromSerialized(
                serialized["schain"]
            )

        if serialized["rchain"] != None:
            self.__receiving_chain = self.__ReceivingChain.fromSerialized(
                serialized["rchain"]
            )

        self.__previous_sending_chain_length = serialized["prev_schain_length"]

        return self

    def step(self, key, chain):
        if chain == "sending":
            self.__previous_sending_chain_length = self.sending_chain_length

            self.__sending_chain = self.__SendingChain(key)

        if chain == "receiving":
            self.__receiving_chain = self.__ReceivingChain(key)

    @property
    def previous_sending_chain_length(self):
        return self.__previous_sending_chain_length

    @property
    def sending_chain_length(self):
        return None if self.__sending_chain == None else self.__sending_chain.length

    @property
    def receiving_chain_length(self):
        return None if self.__receiving_chain == None else self.__receiving_chain.length

    def nextEncryptionKey(self):
        if self.__sending_chain == None:
            raise NotInitializedException(
                "Can not get the next encryption key from the symmetric key ratchet, " +
                "the other's public key is not known yet"
            )

        return self.__sending_chain.next()

    def nextDecryptionKey(self):
        return self.__receiving_chain.next()
