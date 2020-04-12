from abc import ABCMeta, abstractmethod

class AuthenticationFailedException(Exception):
    pass

class DecryptionFailedException(Exception):
    pass

class AEAD(metaclass=ABCMeta):
    """
    Authenticated Encryption with Associated Data (AEAD).
    """

    @staticmethod
    @abstractmethod
    def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            plaintext: The plaintext to encrypt.
            key: The encryption key.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The ciphertext.
        """

        raise NotImplementedError("Create a subclass of AEAD and implement `encrypt`.")

    @staticmethod
    @abstractmethod
    def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            ciphertext: The ciphertext to decrypt.
            key: The decryption key.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The plaintext.

        Raises:
            AuthenticationFailedException: If the message could not be authenticated using the associated
                data.
            DecryptionFailedException: If the decryption failed for a different reason (e.g. invalid padding).
        """

        raise NotImplementedError("Create a subclass of AEAD and implement `decrypt`.")
