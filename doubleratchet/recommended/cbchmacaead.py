from __future__ import absolute_import

from ..aead import AEAD
from ..exceptions import AuthenticationFailedException

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class CBCHMACAEAD(AEAD):
    """
    An implementation of the AEAD interface based on a recommendation by WhisperSystems:

    HKDF is used with SHA-256 or SHA-512 to generate 80 bytes of output. The HKDF salt is
    set to a zero-filled byte sequence equal to the hash's output length. HKDF input key
    material is set to mk. HKDF info is set to an application-specific byte sequence
    distinct from other uses of HKDF in the application.

    The HKDF output is divided into a 32-byte encryption key, a 32-byte authentication
    key, and a 16-byte IV.

    The plaintext is encrypted using AES-256 in CBC mode with PKCS#7 padding, using the
    encryption key and IV from the previous step.

    HMAC is calculated using the authentication key and the same hash function as above.
    The HMAC input is the associated_data prepended to the ciphertext. The HMAC output is
    appended to the ciphertext.
    """

    CRYPTOGRAPHY_BACKEND = default_backend()

    HASH_FUNCTIONS = {
        "SHA-256": hashes.SHA256,
        "SHA-512": hashes.SHA512
    }

    def __init__(self, hash_function, info_string):
        """
        Prepare a CBCHMACAEAD, following a recommendation by WhisperSystems.

        :param hash_function: One of (the strings) "SHA-256" and "SHA-512".
        :param info_string: A bytes-like object encoding a string unique to this usage
            within the application.
        """

        super(CBCHMACAEAD, self).__init__()

        if not hash_function in CBCHMACAEAD.HASH_FUNCTIONS:
            raise ValueError("Invalid value passed for the hash_function parameter.")

        if not isinstance(info_string, bytes):
            raise TypeError("Wrong type passed for the info_string parameter.")

        self.__hash_function = CBCHMACAEAD.HASH_FUNCTIONS[hash_function]
        self.__digest_size = self.__hash_function().digest_size
        self.__info_string = info_string

    def __getHKDFOutput(self, message_key):
        # Prepare the salt, which should be a string of 0x00 bytes with the length of
        # the hash digest
        salt = b"\x00" * self.__digest_size

        # Get 80 bytes from the HKDF calculation
        hkdf_out = HKDF(
            algorithm = self.__hash_function(),
            length    = 80,
            salt      = salt,
            info      = self.__info_string,
            backend   = self.__class__.CRYPTOGRAPHY_BACKEND
        ).derive(message_key)

        # Split these 80 bytes in three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    def __getAES(self, key, iv):
        return Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

    def encrypt(self, plaintext, message_key, ad):
        encryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        # Prepare PKCS#7 padded plaintext
        padder    = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size),
        # CBC mode and the previously created key and iv
        aes_cbc    = self.__getAES(encryption_key, iv).encryptor()
        ciphertext = aes_cbc.update(plaintext) + aes_cbc.finalize()

        # Build the authentication
        auth = hmac.HMAC(
            authentication_key,
            self.__hash_function(),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

        auth.update(ad + ciphertext)

        # Append the authentication to the ciphertext
        return ciphertext + auth.finalize()

    def decrypt(self, ciphertext, message_key, ad):
        auth       = ciphertext[-self.__digest_size:]
        ciphertext = ciphertext[:-self.__digest_size]

        decryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        new_auth = hmac.HMAC(
            authentication_key,
            self.__hash_function(),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

        new_auth.update(ad + ciphertext)

        try:
            new_auth.verify(auth)
        except InvalidSignature:
            raise AuthenticationFailedException()

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size),
        # CBC mode and the previously created key and iv
        aes_cbc   = self.__getAES(decryption_key, iv).decryptor()
        plaintext = aes_cbc.update(ciphertext) + aes_cbc.finalize()
        
        # Remove the PKCS#7 padding from the plaintext
        unpadder  = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return plaintext
