from __future__ import absolute_import

from .ratchet import Ratchet

class SymmetricKeyRatchet(Ratchet):
    def __init__(self, sending_chain_class, receiving_chain_class):
        super(SymmetricKeyRatchet, self).__init__()

        self.__SendingChain = sending_chain_class
        self.__ReceivingChain = receiving_chain_class

        self.__sending_chain = None
        self.__receiving_chain = None

        self.__previous_sending_chain_length = None

    def step(self, key, chain):
        if chain == "sending":
            self.__previous_sending_chain_length = self.sending_chain_length
            self.__sending_chain = self.__SendingChain(sending_chain_key)

        if chain == "receiving":
            self.__receiving_chain = self.__ReceivingChain(receiving_chain_key)

    @property
    def previous_sending_chain_length(self):
        return self.__previous_sending_chain_length

    @property
    def sending_chain_length(self):
        return self.__sending_chain.length

    @property
    def receiving_chain_length(self):
        return self.__receiving_chain.length

    def nextEncryptionKey(self):
        return self.__sending_chain.next()

    def nextDecryptionKey(self):
        return self.__receiving_chain.next()
