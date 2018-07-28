from ..aead import AEAD
from ..exceptions import AuthenticationFailedException

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from hkdf import hkdf_expand, hkdf_extract

import hashlib
import hmac

class CBCHMACAEAD(AEAD):
    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(self, hash_function, info_string):
        super(CBCHMACAEAD, self).__init__()

        self.__hash_function = CBCHMACAEAD.HASH_FUNCTIONS[hash_function]
        self.__digest_size = self.__hash_function().digest_size
        self.__info_string = info_string

    def __getHKDFOutput(self, message_key):
        # Prepare the salt, which should be a string of 0x00 bytes with the length of
        # the hash digest
        salt = b"\x00" * self.__digest_size

        # Get 80 bytes from the HKDF calculation
        hkdf_out = hkdf_expand(
            hkdf_extract(salt, message_key, self.__hash_function),
            self.__info_string.encode("ASCII"),
            80,
            self.__hash_function
        )

        # Split these 80 bytes in three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    def __getAES(self, key, iv):
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())

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
        auth = hmac.new(authentication_key, ad + ciphertext, self.__hash_function)

        # Append the authentication to the ciphertext
        return ciphertext + auth.digest()

    def decrypt(self, ciphertext, message_key, ad):
        auth_size = self.__hash_function().digest_size

        auth       = ciphertext[-auth_size:]
        ciphertext = ciphertext[:-auth_size]

        decryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        new_auth = hmac.new(authentication_key, ad + ciphertext, self.__hash_function)

        if not hmac.compare_digest(auth, new_auth.digest()):
            raise AuthenticationFailedException()

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size),
        # CBC mode and the previously created key and iv
        aes_cbc   = self.__getAES(decryption_key, iv).decryptor()
        plaintext = aes_cbc.update(ciphertext) + aes_cbc.finalize()
        
        # Remove the PKCS#7 padding from the plaintext
        unpadder  = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return plaintext
