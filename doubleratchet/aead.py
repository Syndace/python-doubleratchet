from abc import ABC, abstractmethod


__all__ = [  # pylint: disable=unused-variable
    "AEAD",
    "AuthenticationFailedException",
    "DecryptionFailedException"
]


class AuthenticationFailedException(Exception):
    """
    Raised by :meth:`AEAD.decrypt` in case of authentication failure.
    """


class DecryptionFailedException(Exception):
    """
    Raised by :meth:`AEAD.decrypt` in case of decryption failure.
    """


class AEAD(ABC):
    """
    Authenticated Encryption with Associated Data (AEAD).
    """

    @staticmethod
    @abstractmethod
    async def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            plaintext: The plaintext to encrypt.
            key: The encryption key.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The ciphertext.
        """

    @staticmethod
    @abstractmethod
    async def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        """
        Args:
            ciphertext: The ciphertext to decrypt.
            key: The decryption key.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The plaintext.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
        """
