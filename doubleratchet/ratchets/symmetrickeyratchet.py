from __future__ import absolute_import

from ..exceptions import NotInitializedException
from .ratchet import Ratchet

class SymmetricKeyRatchet(Ratchet):
    """
    An implementation of the Ratchet interface, which internally manages two chains: A
    chain to derive sending keys and a chain to derive receiving keys. The ratchet step
    alternately replaces the sending and the receiving chains with new ones.
    """

    def __init__(self, sending_chain_class, receiving_chain_class):
        """
        Initialize a new SymmetricKeyRatchet.

        :param sending_chain_class: An implementation of the Chain interface to be used
            for the sending chains.
        :param receiving_chain_class: An implementations of the Chain interface to be used
            for the receiving chains.
        """

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
        """
        Perform a rachted step, replacing one of the internally managed chains with a new
        one.

        :param key: A bytes-like object encoding the key to initialize the replacement
            chain with.
        :param chain: The chain to replace. This parameter must be one of the two strings
            "sending" and "receiving".
        """

        if chain == "sending":
            self.__previous_sending_chain_length = self.sending_chain_length

            self.__sending_chain = self.__SendingChain(key)

        if chain == "receiving":
            self.__receiving_chain = self.__ReceivingChain(key)

    @property
    def previous_sending_chain_length(self):
        """
        Get the length of the previous sending chain.

        :returns: Either an integer representing the length of the previous sending chain
            or None, if the current one is the first sending chain.
        """

        return self.__previous_sending_chain_length

    @property
    def sending_chain_length(self):
        """
        Get the length of the current sending chain.

        :returns: Either an integer representing the length of the current sending chain
            or None, if there is no sending chain.
        """

        return None if self.__sending_chain == None else self.__sending_chain.length

    @property
    def receiving_chain_length(self):
        """
        Get the length of the receiving chain.

        :returns: Either an integer representing the length of the receiving chain or
            None, if there is no receiving chain.
        """

        return None if self.__receiving_chain == None else self.__receiving_chain.length

    def nextEncryptionKey(self):
        """
        Use the sending chain to derive the next encryption key.

        :returns: A bytes-like object encoding the next encryption key.
        :raises NotInitializedException: If there is no sending chain yet.
        """

        if self.__sending_chain == None:
            raise NotInitializedException(
                "Can not get the next encryption key from the symmetric key ratchet, " +
                "there is no sending chain yet."
            )

        return self.__sending_chain.next()

    def nextDecryptionKey(self):
        """
        Use the receiving chain to derive the next decryption key.

        :returns: A bytes-like object encoding the next decryption key.
        :raises NotInitializedException: If there is no receiving chain yet.
        """

        if self.__receiving_chain == None:
            raise NotInitializedException(
                "Can not get the next decryption key from the symmetric key ratchet, " +
                "there is no receiving chain yet."
            )

        return self.__receiving_chain.next()
