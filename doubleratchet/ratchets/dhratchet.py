from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    """
    An implementation of the Ratchet interface, which implements a Diffie-Hellman ratchet.

    A Diffie-Hellman ratchet performs its step by calculating shared secrets between
    Diffie-Hellman keys. The Diffie-Hellman ratchet is designed so that two instances can
    synchronize by exchanging the new public keys that are generated in each step.

    For more information, visit the specification by WhisperSystems:
    https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
    """

    def __init__(
        self,
        root_chain,
        key_pair_class,
        own_key = None,
        other_pub = None
    ):
        """
        Initialize a new Diffie-Hellman ratchet.

        :param root_chain: A KDFChain, which receives the Diffie-Hellman key exchange
            output to derive a new chain key.
        :param key_pair_class: An implementations of the KeyPair interface which is used
            for the Diffie-Hellman key management and shared secret calculations.
        :param own_key: An instance of key_pair_class holding the first key pair to
            initialize this ratchet with or None.
        :param other_pub: A bytes-like object encoding the public key of the other
            Diffie-Hellman ratchet to synchronize with or None.
        """

        super(DHRatchet, self).__init__()

        self.__root_chain = root_chain
        self._KeyPair = key_pair_class

        if own_key:
            self.__key = own_key
        else:
            self.__newRatchetKey()

        self.__wrapOtherPub(other_pub)

        if self.__other.pub != None:
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

        self.__key   = self._KeyPair.fromSerialized(serialized["key"])
        self.__other = self._KeyPair.fromSerialized(serialized["other"])

        return self

    def step(self, other_pub, _DEBUG_newRatchetKey = None):
        """
        Perform a rachted step, calculating a new shared secret from the public key and
        deriving new chain keys from this secret.

        New Diffie-Hellman calculations are only performed if the public key is different
        from the previous one.

        :param other_pub: A bytes-like object encoding the public key of the other
            Diffie-Hellman ratchet to synchronize with.
        """

        if self.triggersStep(other_pub):
            self.__wrapOtherPub(other_pub)
            self.__newRootKey("receiving")

            if _DEBUG_newRatchetKey == None:
                self.__newRatchetKey()
            else:
                import logging

                logging.getLogger("doubleratchet.ratchets.dhratchet").error(
                    "WARNING: RUNNING UNSAFE DEBUG-ONLY OPERATION"
                )

                self.__key = _DEBUG_newRatchetKey

            self.__newRootKey("sending")

    def __wrapOtherPub(self, other_pub):
        self.__other = self._KeyPair(pub = other_pub)

    def __newRatchetKey(self):
        self.__key = self._KeyPair.generate()

    def triggersStep(self, other_pub):
        """
        :returns: A boolean indicating whether calling next with this public key would
            trigger a ratchet step.
        """

        return other_pub != self.__other.pub

    def __newRootKey(self, chain):
        self._onNewChainKey(
            self.__root_chain.next(self.__key.getSharedSecret(self.__other)),
            chain
        )

    def _onNewChainKey(self, key, chain):
        raise NotImplementedError

    @property
    def pub(self):
        """
        :returns: A bytes-like object encoding the public key of the current internally
            managed key pair.
        """

        return self.__key.pub

    @property
    def other_pub(self):
        """
        :returns: A bytes-like object encoding the public key of the other Diffie-Hellman
            ratchet to synchronize with.
        """

        return self.__other.pub
