from __future__ import absolute_import

import base64

class KDFChain(object):
    """
    A key derivation function chain.

    A KDFChain is initialized with some data and a KDF, which are stored internally.
    KDFChains provide a "next" method, which takes some input data and uses this input
    data, the internally stored data and the KDF to derive new output data.

    One part of the output data becomes the new internally stored data, overriding the
    previously stored data. The other part becomes the output of the step.

    Because key derivation is a one-way process, KDFChains can move forward but never
    backward.
    """

    def __init__(self, kdf, key = None):
        """
        Initialize a KDFChain using the provided key derivation function and key.

        :param kdf: An instance of the KDF interface.
        :param key: A bytes-like object encoding the key to supply to the key derivation
            function. This parameter MUST NOT be None.
        """

        self.__length = 0
        self.__kdf = kdf
        self.__key = key

    def serialize(self):
        """
        :returns: A serializable Python structure, which contains all the state
            information of this object.

        Use together with the fromSerialized method.
        Here, "serializable" means, that the structure consists of any combination of the
        following types:

        * dictionaries
        * lists
        * strings
        * integers
        * floats
        * booleans
        * None
        """

        return {
            "length": self.__length,
            "key"   : base64.b64encode(self.__key).decode("US-ASCII")
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        """
        :param serialized: A serializable Python object.
        :returns: Return a new instance that was set to the state that was saved into the
            serialized object.

        Use together with the serialize method.
        Notice: You have to pass all positional parameters required by the constructor of
        the class you call fromSerialized on.
        """

        self = cls(*args, **kwargs)
        self.__length = serialized["length"]
        self.__key    = base64.b64decode(serialized["key"].encode("US-ASCII"))

        return self

    def next(self, data):
        """
        Derive a new set of internal and output data from given input data and the data
        stored internally.

        Use the key derivation function to derive new data. The kdf gets supplied with the
        current key and the data passed to this method.

        :param data: A bytes-like object encoding the data to pass to the key derivation
            function.
        :returns: A bytes-like object encoding the output material.
        """

        self.__length += 1

        result = self.__kdf.calculate(self.__key, data, 64)
        self.__key = result[:32]
        return result[32:]

    @property
    def length(self):
        """
        :returns: The number of calls to the "next" method since initializing the chain.
        """

        return self.__length
