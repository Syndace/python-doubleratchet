from typing_extensions import assert_never

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

from .crypto_provider import CryptoProvider, HashFunction
from .. import aead


__all__ = [  # pylint: disable=unused-variable
    "CryptoProviderImpl"
]


def get_hash_algorithm(hash_function: HashFunction) -> hashes.HashAlgorithm:
    """
    Args:
        hash_function: Identifier of a hash function.

    Returns:
        The implementation of the hash function as a cryptography
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` object.
    """

    if hash_function is HashFunction.SHA_256:
        return hashes.SHA256()
    if hash_function is HashFunction.SHA_512:
        return hashes.SHA512()
    if hash_function is HashFunction.SHA_512_256:
        return hashes.SHA512_256()

    return assert_never(hash_function)


class CryptoProviderImpl(CryptoProvider):
    """
    Cryptography provider based on the Python package `cryptography <https://github.com/pyca/cryptography>`_.
    """

    @staticmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        return HKDF(
            algorithm=get_hash_algorithm(hash_function),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(key_material)

    @staticmethod
    async def hmac_calculate(key: bytes, hash_function: HashFunction, data: bytes) -> bytes:
        hmac = HMAC(key, get_hash_algorithm(hash_function), backend=default_backend())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    async def aes_cbc_encrypt(key: bytes, initialization_vector: bytes, plaintext: bytes) -> bytes:
        # Prepare PKCS#7 padded plaintext
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-CBC
        aes = Cipher(
            algorithms.AES(key),
            modes.CBC(initialization_vector),
            backend=default_backend()
        ).encryptor()

        return aes.update(padded_plaintext) + aes.finalize()  # pylint: disable=no-member

    @staticmethod
    async def aes_cbc_decrypt(key: bytes, initialization_vector: bytes, ciphertext: bytes) -> bytes:
        # Decrypt the plaintext using AES-CBC
        try:
            aes = Cipher(
                algorithms.AES(key),
                modes.CBC(initialization_vector),
                backend=default_backend()
            ).decryptor()
            padded_plaintext = aes.update(ciphertext) + aes.finalize()  # pylint: disable=no-member
        except ValueError as e:
            raise aead.DecryptionFailedException("Decryption failed.") from e

        # Remove the PKCS#7 padding from the plaintext
        try:
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            raise aead.DecryptionFailedException("Plaintext padded incorrectly.") from e
