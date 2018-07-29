from __future__ import absolute_import

from .kdfchain import KDFChain

class ConstKDFChain(KDFChain):
    def __init__(self, kdf, constant, key = None):
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

    def next(self):
        return super(ConstKDFChain, self).next(self.__constant)
