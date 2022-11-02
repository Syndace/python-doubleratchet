from abc import abstractmethod
from typing import Tuple

from .crypto_provider import HashFunction
from .crypto_provider_impl import CryptoProviderImpl
from .. import aead


__all__ = [  # pylint: disable=unused-variable
    "AEAD"
]


class AEAD(aead.AEAD):
    """
    An implementation of Authenticated Encryption with Associated Data using AES-256 in CBC mode, HKDF and
    HMAC with SHA-256 or SHA-512:

    HKDF is used with SHA-256 or SHA-512 to generate 80 bytes of output. The HKDF salt is set to a zero-filled
    byte sequence equal to the digest size of the hash function. HKDF input key material is set to AEAD key.
    HKDF info is set to an application-specific byte sequence distinct from other uses of HKDF in the
    application.

    The HKDF output is divided into a 32-byte encryption key, a 32-byte authentication key, and a 16-byte IV.

    The plaintext is encrypted using AES-256 in CBC mode with PKCS#7 padding, using the encryption key and IV
    from the previous step.

    HMAC is calculated using the authentication key and the same hash function as above. The HMAC input is the
    associated_data prepended to the ciphertext. The HMAC output is appended to the ciphertext.
    """

    @staticmethod
    @abstractmethod
    def _get_hash_function() -> HashFunction:
        pass

    @staticmethod
    @abstractmethod
    def _get_info() -> bytes:
        pass

    @classmethod
    async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function()

        encryption_key, authentication_key, iv = await cls.__derive(key, hash_function, cls._get_info())

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, after padding it with PKCS#7
        ciphertext = await CryptoProviderImpl.aes_cbc_encrypt(encryption_key, iv, plaintext)

        # Calculate the authentication tag
        auth = await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            hash_function,
            associated_data + ciphertext
        )

        # Append the authentication tag to the ciphertext
        return ciphertext + auth

    @classmethod
    async def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function()

        decryption_key, authentication_key, iv = await cls.__derive(key, hash_function, cls._get_info())

        # Split the authentication tag from the ciphertext
        auth = ciphertext[-hash_function.hash_size:]
        ciphertext = ciphertext[:-hash_function.hash_size]

        # Calculate and verify the authentication tag
        new_auth = await CryptoProviderImpl.hmac_calculate(
            authentication_key,
            hash_function,
            associated_data + ciphertext
        )

        if new_auth != auth:
            raise aead.AuthenticationFailedException("Authentication tags do not match.")

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV, and unpad the resulting plaintext with PKCS#7
        return await CryptoProviderImpl.aes_cbc_decrypt(decryption_key, iv, ciphertext)

    @staticmethod
    async def __derive(key: bytes, hash_function: HashFunction, info: bytes) -> Tuple[bytes, bytes, bytes]:
        # Prepare the salt, a zero-filled byte sequence with the size of the hash digest
        salt = b"\x00" * hash_function.hash_size

        # Derive 80 bytes
        hkdf_out = await CryptoProviderImpl.hkdf_derive(
            hash_function=hash_function,
            length=80,
            salt=salt,
            info=info,
            key_material=key
        )

        # Split these 80 bytes into three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]
