from ..exceptions import NotInitializedException
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
            self.__sending_chain = self.__SendingChain(key)

        if chain == "receiving":
            self.__receiving_chain = self.__ReceivingChain(key)

    @property
    def previous_sending_chain_length(self):
        return self.__previous_sending_chain_length

    @property
    def sending_chain_length(self):
        return self.__sending_chain.length if self.__sending_chain else None

    @property
    def receiving_chain_length(self):
        return self.__receiving_chain.length if self.__receiving_chain else None

    def nextEncryptionKey(self):
        if self.__sending_chain == None:
            raise NotInitializedException(
                "Can not get the next encryption key from the symmetric key ratchet, " +
                "the other's public key is not known yet"
            )

        return self.__sending_chain.next()

    def nextDecryptionKey(self):
        return self.__receiving_chain.next()
