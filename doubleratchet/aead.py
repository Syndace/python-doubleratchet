class AEAD(object):
    """
    Authenticated Encryption with Associated Data (AEAD).
    """

    def encrypt(self, plaintext, key, ad):
        """
        Encrypt given plaintext using given key and authenticating using given associated
        data.

        :param plaintext: A bytes-like object encoding the data to encrypt.
        :param key: A bytes-like object encoding the key to encrypt with.
        :param ad: A bytes-like object encoding the associated data to authenticate with.
        :returns: A bytes-like object encoding the encrypted data (the ciphertext).
        """

        raise NotImplementedError

    def decrypt(self, ciphertext, key, ad):
        """
        Decrypt given ciphertext using given key and check validity of the authentication
        using given associated data.

        :param ciphertext: A bytes-like object encoding the data to decrypt.
        :param key: A bytes-like object encoding the key to decrypt with.
        :param ad: A bytes-like object encoding the associated data to authenticate with.
        :returns: A bytes-like object encoding the decrypted data (the plaintext).
        :raises AuthenticationFailedException: If the message could not be authenticated
            using the associated data.
        """

        raise NotImplementedError
