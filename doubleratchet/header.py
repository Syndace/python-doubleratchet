class Header(object):
    """
    Each message encrypted with the double ratchet protocol comes with a header in
    addition to the ciphertext body.
    """

    def __init__(self, dh_pub, n, pn):
        """
        Initiate a message header.

        :param dh_pub: A bytes-like object encoding the new public key of the senders
            diffie-hellman ratchet.
        :param n: The current length of the senders sending chain, as an integer.
        :param pn: The length of the senders previous sending chain, as an integer. This
            enables the receiver to store keys for skipped messages of the previous chain.
        """

        self.__dh_pub = dh_pub
        self.__n  = n
        self.__pn = pn

    @property
    def dh_pub(self):
        """
        :returns: A bytes-like object encoding the new public key of the senders
            diffie-hellman ratchet.
        """

        return self.__dh_pub

    @property
    def n(self):
        """
        :returns: The current length of the senders sending chain, as an integer.
        """

        return self.__n

    @property
    def pn(self):
        """
        :returns: The length of the senders previous sending chain, as an integer. This
            enables the receiver to store keys for skipped messages of the previous chain.
        """

        return self.__pn
