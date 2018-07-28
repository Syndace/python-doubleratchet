class DoubleRatchetConfig(object):
    def __init__(self, symmetric_key_ratchet, aead, ad, message_key_store_max):
        self.__symmetric_key_ratchet = symmetric_key_ratchet
        self.__aead = aead
        self.__ad = ad
        self.__message_key_store_max = message_key_store_max

    @property
    def skr(self):
        return self.__symmetric_key_ratchet

    @property
    def aead(self):
        return self.__aead

    @property
    def ad(self):
        return self.__ad

    @property
    def mk_store_max(self):
        return self.__message_key_store_max

class DHRatchetConfig(object):
    def __init__(self, root_chain, encryption_key_pair_class, own_key = None, other_enc = None):
        self.__root_chain = root_chain
        self.__encryption_key_pair_class = encryption_key_pair_class
        self.__own_key = own_key
        self.__other_enc = other_enc

    @property
    def root_chain(self):
        return self.__root_chain

    @property
    def EncryptionKeyPair(self):
        return self.__encryption_key_pair_class

    @property
    def own_key(self):
        return self.__own_key

    @property
    def other_enc(self):
        return self.__other_enc

class Config(object):
    def __init__(self, double_ratchet_config, dh_ratchet_config):
        self.__double_ratchet_config = double_ratchet_config
        self.__dh_ratchet_config = dh_ratchet_config

    @property
    def dr_config(self):
        return self.__double_ratchet_config

    @property
    def dh_config(self):
        return self.__dh_ratchet_config
