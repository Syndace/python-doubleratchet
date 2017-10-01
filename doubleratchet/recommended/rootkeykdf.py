from __future__ import absolute_import

from ..exceptions import InvalidHashFunctionException
from ..kdf import KDF

from hkdf import hkdf_expand, hkdf_extract

import hashlib

class RootKeyKDF(KDF):
    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(self, hash_function, info_string):
        super(RootKeyKDF, self).__init__()

        if not hash_function in RootKeyKDF.HASH_FUNCTIONS:
            raise InvalidHashFunctionException("The hash function parameter must be any key of RootKeyKDF.HASH_FUNCTIONS")

        self.__hash_function = RootKeyKDF.HASH_FUNCTIONS[hash_function]
        self.__info_string = info_string
    
    def calculate(self, key, data, length):
        """
        As recommended:
        - The root key as salt
        - The data as input key material
        - An application defined info string
        """

        return hkdf_expand(hkdf_extract(key, data, self.__config.hash_function), self.__info_string, length, self.__config.hash_function)
