from .kdfchain import KDFChain

class ConstKDFChain(KDFChain):
    def __init__(self, key, kdf, constant):
        super(ConstKDFChain, self).__init__(key, kdf)

        self.__constant = constant

    def next(self):
        return super(ConstKDFChain, self).next(self.__constant)
