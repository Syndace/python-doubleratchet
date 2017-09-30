from __future__ import absolute_import

from ..exceptions import InvalidKDFException
from ..exceptions import InvalidKeyException
from ..kdf import KDF

class KDFChain(object):
    def __init__(self, key, kdf):
        """
        Initialize a KDFChain using the provided key and KDF.
        """

        if not isinstance(key, bytes) or len(key) != 32:
            raise InvalidKeyException("The chain key must be 32 bytes")

        self.__key = key

        if not isinstance(kdf, KDF):
            raise InvalidKDFException("The provided KDF must be an instance of KDF")

        self.__kdf = kdf

    def next(self, data):
        """
        Calculate the next key and output data from given input data.
        """

        result = self.__kdf.calculate(self.__key, data, 64)
        self.__key = result[:32]
        return result[32:]
