from __future__ import absolute_import

from .ratchet import Ratchet

class SymmetricKeyRatchet(Ratchet):
    def __init__(self, sending_chain_class, receiving_chain_class):
        super(SymmetricKeyRatchet, self).__init__()

        self.__SendingChain = sending_chain_class
        self.__ReceivingChain = receiving_chain_class

        self.__sending_chain = None
        self.__receiving_chain = None

    def _newSendingChainKey(self, sending_chain_key):
        self.__sending_chain = self.__SendingChain(sending_chain_key)

    def _newReceivingChainKey(self, receiving_chain_key):
        self.__receiving_chain = self.__ReceivingChain(receiving_chain_key)

    def decrypt(self, message):
        key = self.__receiving_chain.next()
        # TODO

    def encrypt(self, message):
        key = self.__sending_chain.next()
        # TODO
