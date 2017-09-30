from __future__ import absolute_import

from .ratchet import Ratchet

class SymmetricKeyRatchet(Ratchet):
    def __init__(self, root_chain_class, sending_chain_class, receiving_chain_class, root_chain_key):
        super(SymmetricKeyRatchet, self).__init__()

        self.__RootChain = root_chain_class
        self.__SendingChain = sending_chain_class
        self.__ReceivingChain = receiving_chain_class

        self.__sending_chain = None
        self.__receiving_chain = None
        self.__root_chain = self.__RootChain(root_chain_key)

    def _deriveNewSendingChain(self, shared_secret):
        sending_chain_key = self.__root_chain.next(shared_secret)
        self.__sending_chain = self.__SendingChain(sending_chain_key)
    
    def _deriveNewReceivingChain(self, shared_secret):
        receiving_chain_key = self.__root_chain.next(shared_secret)
        self.__receiving_chain = self.__ReceivingChain(receiving_chain_key)

    def decrypt(self, message):
        key = self.__receiving_chain.next()
        # TODO

    def encrypt(self, message):
        key = self.__sending_chain.next()
        # TODO
