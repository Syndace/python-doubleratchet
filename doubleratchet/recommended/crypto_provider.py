from abc import ABC, abstractmethod
import enum
from typing_extensions import assert_never


__all__ = [  # pylint: disable=unused-variable
    "CryptoProvider",
    "HashFunction"
]


@enum.unique
class HashFunction(enum.Enum):
    """
    Enumeration of the three hash functions that can be used with
    :class:`doubleratchet.recommended.aead_aes_hmac.AEAD`, :class:`doubleratchet.recommended.kdf_hkdf.KDF` and
    :class:`doubleratchet.recommended.kdf_separate_hmacs.KDF`. The three hash functions are SHA-256, SHA-512,
    and truncated SHA-512 to 256 bits.
    """

    SHA_256: str = "SHA_256"
    SHA_512: str = "SHA_512"
    SHA_512_256: str = "SHA_512_256"

    @property
    def hash_size(self) -> int:
        """
        Returns:
            The byte size of the hashes produced by this hash function.
        """

        if self is HashFunction.SHA_256:
            return 32
        if self is HashFunction.SHA_512:
            return 64
        if self is HashFunction.SHA_512_256:
            return 32

        return assert_never(self)


class CryptoProvider(ABC):
    """
    Abstraction of the cryptographic operations needed by this package to allow for different backend
    implementations.
    """

    @staticmethod
    @abstractmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        """
        Args:
            hash_function: The hash function to parameterize the HKDF with.
            length: The number of bytes to derive.
            salt: The salt input for the HKDF.
            info: The info input for the HKDF.
            key_material: The input key material to derive from.

        Returns:
            The derived key material.
        """

    @staticmethod
    @abstractmethod
    async def hmac_calculate(key: bytes, hash_function: HashFunction, data: bytes) -> bytes:
        """
        Args:
            key: The authentication key.
            hash_function: The hash function to parameterize the HMAC with.
            data: The data to authenticate.

        Returns:
            The authentication tag.
        """

    @staticmethod
    @abstractmethod
    async def aes_cbc_encrypt(key: bytes, initialization_vector: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext with AES-CBC. The plaintext is padded with PKCS#7 before encryption.

        Args:
            key: The AES key. Either 128, 192 or 256 bits.
            initialization_vector: The initialization vector as needed by AES-CBC.
            plaintext: The plaintext.

        Returns:
            The ciphertext obtained by padding the plaintext with PKCS#7 and then encrypting it with AES-CBC.
        """

    @staticmethod
    @abstractmethod
    async def aes_cbc_decrypt(key: bytes, initialization_vector: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt plaintext with AES-CBC. The plaintext is unpadded with PKCS#7 after decryption.

        Args:
            key: The AES key. Either 128, 192 or 256 bits.
            initialization_vector: The initialization vector as needed by AES-CBC.
            ciphertext: The ciphertext.

        Returns:
            The plaintext obtained by decrypting it with AES-CBC and unpadding the result with PKCS#7.

        Raises:
            DecryptionFailedException: on decryption or unpadding failure.
        """
