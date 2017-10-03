from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(self, config):
        super(DHRatchet, self).__init__()

        self.__config = config.dh_config

        if self.__config.own_key:
            self.__key = self.__config.own_key
        else:
            self.__newRatchetKey()

        self.__wrapOtherPub(self.__config.other_pub)

        if self.__other.pub:
            self.__newRootKey("sending")

    def step(self, other_pub):
        if self.triggersStep(other_pub):
            self.__wrapOtherPub(other_pub)
            self.__newRootKey("receiving")
            self.__newRatchetKey()
            self.__newRootKey("sending")

    def __wrapOtherPub(self, other_pub):
        self.__other = self.__config.KeyQuad(public_key = other_pub)

    def __newRatchetKey(self):
        self.__key = self.__config.KeyQuad.generate()

    def triggersStep(self, other_pub):
        return other_pub != self.__other.pub

    def __newRootKey(self, chain):
        self._onNewChainKey(self.__config.root_chain.next(self.__key.getSharedSecret(self.__other)), chain)

    def _onNewChainKey(self, key, chain):
        raise NotImplementedError

    @property
    def pub(self):
        return self.__key.pub

    @property
    def other_pub(self):
        return self.__other.pub
