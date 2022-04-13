from abc import abstractmethod
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import _CipherContext
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7, _PKCS7PaddingContext, _PKCS7UnpaddingContext

from .hash_function import HashFunction
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
        raise NotImplementedError("Create a subclass and override `_get_hash_function`.")

    @staticmethod
    @abstractmethod
    def _get_info() -> bytes:
        raise NotImplementedError("Create a subclass and override `_get_info`.")

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function().as_cryptography

        encryption_key, authentication_key, iv = cls.__derive(key, hash_function, cls._get_info())

        # Prepare PKCS#7 padded plaintext
        padder: _PKCS7PaddingContext = PKCS7(128).padder()  # type: ignore[no-untyped-call]
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        aes: _CipherContext = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()  # type: ignore[no-untyped-call]
        ciphertext = aes.update(padded_plaintext) + aes.finalize()

        # Calculate the authentication tag
        auth = hmac.HMAC(authentication_key, hash_function, backend=default_backend())
        auth.update(associated_data)
        auth.update(ciphertext)

        # Append the authentication tag to the ciphertext
        return ciphertext + auth.finalize()

    @classmethod
    def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function().as_cryptography

        decryption_key, authentication_key, iv = cls.__derive(key, hash_function, cls._get_info())

        # Split the authentication tag from the ciphertext
        auth = ciphertext[-hash_function.digest_size:]
        ciphertext = ciphertext[:-hash_function.digest_size]

        # Calculate and verify the authentication tag
        new_auth = hmac.HMAC(authentication_key, hash_function, backend=default_backend())
        new_auth.update(associated_data)
        new_auth.update(ciphertext)

        try:
            new_auth.verify(auth)
        except InvalidSignature as e:
            raise aead.AuthenticationFailedException() from e

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        try:
            aes: _CipherContext = Cipher(
                algorithms.AES(decryption_key),
                modes.CBC(iv),
                backend=default_backend()
            ).decryptor()  # type: ignore[no-untyped-call]
            padded_plaintext = aes.update(ciphertext) + aes.finalize()
        except ValueError as e:
            raise aead.DecryptionFailedException("Decryption failed.") from e

        # Remove the PKCS#7 padding from the plaintext
        try:
            unpadder: _PKCS7UnpaddingContext = PKCS7(128).unpadder()  # type: ignore[no-untyped-call]
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            raise aead.DecryptionFailedException("Plaintext padded incorrectly.") from e

        return plaintext

    @staticmethod
    def __derive(key: bytes, hash_function: hashes.HashAlgorithm, info: bytes) -> Tuple[bytes, bytes, bytes]:
        # Prepare the salt, a zero-filled byte sequence with the size of the hash digest
        salt = b"\x00" * hash_function.digest_size

        # Derive 80 bytes
        hkdf_out = HKDF(
            algorithm=hash_function,
            length=80,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(key)

        # Split these 80 bytes into three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]
