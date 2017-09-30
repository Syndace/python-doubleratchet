from __future__ import absolute_import

from ..kdf import KDF

from hkdf import hkdf_expand, hkdf_extract

class HKDF(KDF):
    def __init__(self, hash_function):
        super(HKDF, self).__init__()
        self.__hash_function = hash_function
    
    def calculate(self, key, data, length):
        salt = self._calculateSalt(key, data, length)
        return hkdf_expand(hkdf_extract(self._, key, self.__hash_function), data, length, self.__hash_function)

    def _calculateSalt(self, key, data, length):
        raise NotImplementedError
