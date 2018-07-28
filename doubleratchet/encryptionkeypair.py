class EncryptionKeyPair(object):
    def __init__(self, enc = None, dec = None):
        raise NotImplementedError

    @classmethod
    def generate(cls):
        raise NotImplementedError

    def getSharedSecret(self, other):
        raise NotImplementedError

    @property
    def enc(self):
        raise NotImplementedError

    @property
    def dec(self):
        raise NotImplementedError
