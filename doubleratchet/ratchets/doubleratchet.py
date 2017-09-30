from __future__ import absolute_import

from .dhratchet import DHRatchet

class DoubleRatchet(DHRatchet):
    def __init__(self, symmetric_key_ratchet, key_quad_class, key = None, other_pub = None):
        super(DoubleRatchet, self).__init__(key_quad_class, key, other_pub)

        self.__symmetric_key_ratchet = symmetric_key_ratchet

    def _onSharedSecret(self, shared_secret, shared_secret_type):
        if shared_secret_type == 2: # Sending chain
            self.__symmetric_key_ratchet._deriveNewSendingChain(shared_secret)

        if shared_secret_type == 1: # Receiving chain
            self.__symmetric_key_ratchet._deriveNewReceivingChain(shared_secret)
