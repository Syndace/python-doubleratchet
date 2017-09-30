from __future__ import absolute_import

from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(self, key_quad_class, key = None, other_pub = None):
        super(DHRatchet, self).__init__()

        self.__KeyQuad = key_quad_class

        self.__key = key if key else self.__KeyQuad.generate()

        self.__other = self.__KeyQuad(public_key = other_pub)

        if self.__other.pub:
            self._onSharedSecret(self.__key.getSharedSecret(self.__other), 2)

    def step(self, other_pub):
        if other_pub != self.__other.pub:
            self.__other = self.__KeyQuad(public_key = other_pub)

            self._onSharedSecret(self.__key.getSharedSecret(self.__other), 1)

            self.__key = self.__KeyQuad.generate()

            self._onSharedSecret(self.__key.getSharedSecret(self.__other), 2)

    @staticmethod
    def _onSharedSecret(shared_secret, shared_secret_type):
        pass

    @property
    def pub(self):
        return self.__key.pub
