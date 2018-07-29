from __future__ import absolute_import

import base64

from .chain import Chain

class KDFChain(Chain):
    def __init__(self, kdf, key = None):
        """
        Initialize a KDFChain using the provided key and KDF.
        """

        self.__kdf = kdf
        self.__key = key
        self.__length = 0

    def serialize(self):
        return {
            "super"  : super(KDFChain, self).serialize(),
            "key"    : base64.b64encode(self.__key).decode("US-ASCII"),
            "length" : self.__length
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(KDFChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        self.__key    = base64.b64decode(serialized["key"].encode("US-ASCII"))
        self.__length = serialized["length"]

        return self

    def next(self, data):
        """
        Calculate the next key and output data from given input data.
        """

        self.__length += 1

        result = self.__kdf.calculate(self.__key, data, 64)
        self.__key = result[:32]
        return result[32:]

    @property
    def length(self):
        return self.__length
