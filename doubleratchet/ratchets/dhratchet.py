from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(self, root_chain, key_quad_class, other_pub = None):
        super(DHRatchet, self).__init__()

        self.__root_chain = root_chain

        self.__KeyQuad = key_quad_class

        self.__key = self.__KeyQuad.generate()
        self.__other = self.__KeyQuad(public_key = other_pub)

        if self.__other.pub:
            self._onNewKey(self.__root_chain.next(self.__key.getSharedSecret(self.__other)), "sending")

    def step(self, other_pub):
        if other_pub != self.__other.pub:
            self.__other = self.__KeyQuad(public_key = other_pub)

            self._onNewKey(self.__root_chain.next(self.__key.getSharedSecret(self.__other)), "receiving")

            self.__key = self.__KeyQuad.generate()

            self._onNewKey(self.__root_chain.next(self.__key.getSharedSecret(self.__other)), "sending")

    def _onNewKey(self, key, chain):
        pass

    @property
    def pub(self):
        return self.__key.pub
