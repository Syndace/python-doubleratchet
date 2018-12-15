from __future__ import absolute_import

from .kdfchain import KDFChain

class ConstKDFChain(KDFChain):
    """
    An implementation of the Chain interface that uses a key derivation function to
    provide the chain step mechanism. In contrast to the KDFChain implementation, this
    implementation passes the same constant data to the key derivation function on every
    call to next.
    """

    def __init__(self, constant, *args, **kwargs):
        """
        Initialize a ConstKDFChain, which uses constant input data instead of passed data
        on chains steps.

        :param constant: The constant data to pass to the next method on each step.
        """

        super(ConstKDFChain, self).__init__(*args, **kwargs)

        self.__constant = constant

    def next(self, data = None):
        """
        Use the key derivation function to derive new data. The kdf gets supplied with the
        current key and the constant input data set using the constructor.

        :returns: A bytes-like object encoding the output material.
        """

        return super(ConstKDFChain, self).next(self.__constant)
