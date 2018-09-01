from __future__ import absolute_import

import base64

from .chain import Chain

class KDFChain(Chain):
    """
    An implementation of the Chain interface that uses a key derivation function to
    provide the chain step mechanism.
    """

    def __init__(self, kdf, key = None):
        """
        Initialize a KDFChain using the provided key derivation function and key.

        :param kdf: An instance of the KDF interface.
        :param key: A bytes-like object encoding the key to supply to the key derivation
            function. This parameter MUST NOT be None.
        """

        super(KDFChain, self).__init__()

        self.__kdf = kdf
        self.__key = key

    def serialize(self):
        return {
            "super" : super(KDFChain, self).serialize(),
            "key"   : base64.b64encode(self.__key).decode("US-ASCII")
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(KDFChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        self.__key = base64.b64decode(serialized["key"].encode("US-ASCII"))

        return self

    def next(self, data):
        """
        Use the key derivation function to derive new data. The kdf gets supplied with the
        current key and the data passed to this method.

        :param data: A bytes-like object encoding the data to pass to the key derivation
            function.
        :returns: A bytes-like object encoding the output material.
        """

        super(KDFChain, self).next()

        result = self.__kdf.calculate(self.__key, data, 64)
        self.__key = result[:32]
        return result[32:]
