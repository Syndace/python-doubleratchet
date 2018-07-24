class Header(object):
    def __init__(self, dh_enc, n, pn):
        self.__dh_enc = dh_enc
        self.__n = n
        self.__pn = pn

    @property
    def dh_enc(self):
        return self.__dh_enc

    @property
    def n(self):
        return self.__n

    @property
    def pn(self):
        return self.__pn

    def __str__(self):
        return (
            "N: " +
            str(self.n) +
            "\nPN: " +
            str(self.pn) +
            "\nDH enc: " +
            ":".join("{:02x}".format(c) for c in self.dh_enc)
        )
