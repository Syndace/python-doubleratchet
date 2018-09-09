from __future__ import absolute_import

from .kdfchain import KDFChain

class ConstKDFChain(KDFChain):
    """
    An implementation of the Chain interface that uses a key derivation function to
    provide the chain step mechanism. In contrast to the KDFChain implementation, this
    implementation passes the same constant data to the key derivation function on every
    call to next.
    """

    def __init__(self, kdf, constant, key = None):
        """
        Initialize a ConstKDFChain using the provided key derivation function, constant
        data and key.

        :param kdf: An instance of the KDF interface.
        :param constant: The constant data to supply to the key derivation function on
            every chain step.
        :param key: A bytes-like object encoding the key to supply to the key derivation
            function. This parameter MUST NOT be None.
        """

        super(ConstKDFChain, self).__init__(kdf, key)

        self.__constant = constant

    def serialize(self):
        return {
            "super": super(ConstKDFChain, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(ConstKDFChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

    def next(self, data = None):
        """
        Use the key derivation function to derive new data. The kdf gets supplied with the
        current key and the constant input data set using the constructor.

        :returns: A bytes-like object encoding the output material.
        """

        return super(ConstKDFChain, self).next(self.__constant)
