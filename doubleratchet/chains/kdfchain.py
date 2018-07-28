class KDFChain(object):
    def __init__(self, key, kdf):
        """
        Initialize a KDFChain using the provided key and KDF.
        """

        self.__key = key
        self.__kdf = kdf
        self.__length = 0

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
