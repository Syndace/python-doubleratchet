from .ratchet import Ratchet

class DHRatchet(Ratchet):
    def __init__(self, config):
        super(DHRatchet, self).__init__()

        self.__config = config.dh_config

        if self.__config.own_key:
            self.__key = self.__config.own_key
        else:
            self.__newRatchetKey()

        self.__wrapOtherEnc(self.__config.other_enc)

        if self.__other.enc:
            self.__newRootKey("sending")

    def step(self, other_enc):
        if self.triggersStep(other_enc):
            self.__wrapOtherEnc(other_enc)
            self.__newRootKey("receiving")
            self.__newRatchetKey()
            self.__newRootKey("sending")

    def __wrapOtherEnc(self, other_enc):
        self.__other = self.__config.EncryptionKeyPair(enc = other_enc)

    def __newRatchetKey(self):
        self.__key = self.__config.EncryptionKeyPair.generate()

    def triggersStep(self, other_enc):
        return other_enc != self.__other.enc

    def __newRootKey(self, chain):
        self._onNewChainKey(
            self.__config.root_chain.next(self.__key.getSharedSecret(self.__other)),
            chain
        )

    def _onNewChainKey(self, key, chain):
        raise NotImplementedError

    @property
    def enc(self):
        return self.__key.enc

    @property
    def other_enc(self):
        return self.__other.enc
