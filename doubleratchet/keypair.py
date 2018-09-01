class KeyPair(object):
    """
    The interface of a key pair. A key pair is a pair consisting of a private and a public
    key used for en- and decryption.
    """

    def __init__(self, priv = None, pub = None):
        """
        Initiate a KeyPair instance using the key information provided as parameters.

        :param priv: The private key as a bytes-like object or None.
        :param pub: The public key as a bytes-like object or None.

        If both the private and the public key are None, a new KeyPair gets generated.
        """

        raise NotImplementedError

    def serialize(self):
        """
        Return a serializable Python structure, which contains all the state information
        of this object.
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

        return None

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        """
        Return a new instance that was set to the state that was saved into the serialized
        object.
        Use together with the serialize method.
        Notice: You have to pass all positional parameters required by the constructor of
        the class you call fromSerialized on.
        """

        return cls(*args, **kwargs)

    @property
    def priv(self):
        """
        Return a bytes-like object representing the private key.
        """

        raise NotImplementedError

    @property
    def pub(self):
        """
        Return a bytes-like object representing the public key.
        """

        raise NotImplementedError

    def getSharedSecret(self, other):
        """
        Get a shared secret between the keys stored by this instance and the keys stored
        by the other instance.

        The shared secrets are generated, so that following equation is True: ::

            shared_secret(A.priv, B.pub) == shared_secret(B.priv, A.pub)

        :param other: An instance of the KeyPair class.
        :returns: The shared secret, as a bytes-like object.
        :raises MissingKeyException: If any key is missing to complete this operation. The
            exception message will contain (human-readable) details.
        """

        raise NotImplementedError
