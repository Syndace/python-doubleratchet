class Header(object):
    def __init__(self, dh_pub, n, pn):
        self.__dh_pub = dh_pub
        self.__n = n
        self.__pn = pn

    @property
    def dh_pub(self):
        return self.__dh_pub

    @property
    def n(self):
        return self.__n

    @property
    def pn(self):
        return self.__pn
