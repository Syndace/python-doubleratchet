class KDF(object):
    """
    A key derivation function.
    """

    def calculate(self, key, data, length):
        """
        Use the key and the given input data to derive an output key of given length.

        :param key: A bytes-like object encoding the key to use for derivation.
        :param data: A bytes-like object encoding the data to use for derivation.
        :param length: The length of the key to derive, as an integer.
        :returns: A bytes-like object with the requested length encoding the derived key.
        """

        raise NotImplementedError
