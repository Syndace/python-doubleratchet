from __future__ import absolute_import

from .dhratchet import DHRatchet

class DoubleRatchet(DHRatchet):
    def __init__(self, symmetric_key_ratchet, *args):
        super(DoubleRatchet, self).__init__(*args)

        self.__symmetric_key_ratchet = symmetric_key_ratchet

    def _onNewKey(self, key, chain):
        if chain == "sending":
            self.__symmetric_key_ratchet._newSendingChainKey(key)

        if chain == "receiving":
            self.__symmetric_key_ratchet._newReceivingChainKey(key)
