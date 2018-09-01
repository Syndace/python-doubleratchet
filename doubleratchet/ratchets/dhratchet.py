from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(
        self,
        root_chain,
        key_pair_class,
        own_key = None,
        other_pub = None
    ):
        super(DHRatchet, self).__init__()

        self.__root_chain = root_chain
        self._KeyPair = key_pair_class

        if own_key:
            self.__key = own_key
        else:
            self.__newRatchetKey()

        self.__wrapOtherPub(other_pub)

        if self.__other.pub:
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
        self.__key = self._KeyPair()

    def triggersStep(self, other_pub):
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
        return self.__key.pub

    @property
    def other_pub(self):
        return self.__other.pub
