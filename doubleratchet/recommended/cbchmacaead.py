from __future__ import absolute_import

from ..aead import AEAD
from ..exceptions import AuthenticationFailedException

from Crypto.Cipher import AES
from Crypto.Util import Padding
from hkdf import hkdf_expand, hkdf_extract

import hashlib
import hmac

class CBCHMACAEAD(AEAD):
    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(self, hash_function, info_string, auth_tag_size):
        super(CBCHMACAEAD, self).__init__()

        self.__hash_function = CBCHMACAEAD.HASH_FUNCTIONS[hash_function]
        self.__digest_size = self.__hash_function().digest_size
        self.__info_string = info_string
        self.__auth_tag_size = auth_tag_size

    def __getHKDFOutput(self, message_key):
        # Prepare the salt, which should be a string of 0x00 bytes with the length of the hash digest
        salt = b"\x00" * self.__digest_size

        # Get 80 bytes from the HKDF calculation
        hkdf_out = hkdf_expand(hkdf_extract(salt, message_key, self.__hash_function), self.__info_string, 80, self.__hash_function)

        # Split these 80 bytes in three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    def __getAES(self, key, iv):
        return AES.new(key, AES.MODE_CBC, iv = iv)

    def __authenticate(self, ciphertext, ad, authentication_key):
        # Append the ciphertext to the associated data as input for the HMAC calculation
        hmac_input = ad + ciphertext

        # Calculate the HMAC with the same hash function as the hkdf, use the authentication key from the HKDF result as key and ad+ciphertext as input
        return hmac.new(authentication_key, hmac_input, self.__hash_function).digest()[:self.__auth_tag_size]

    def encrypt(self, plaintext, message_key, ad):
        encryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        # Prepare PKCS#7 padded plaintext
        plaintext = Padding.pad(plaintext, 16, "pkcs7")

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size), CBC mode and the previously created key and iv
        ciphertext = self.__getAES(encryption_key, iv).encrypt(plaintext)

        authentication = self.__authenticate(ciphertext, ad, authentication_key)

        # Append the authentication to the ciphertext
        return ciphertext + authentication

    def decrypt(self, ciphertext, message_key, ad):
        # Split the authentication and the actual ciphertext
        authentication_old = ciphertext[-self.__auth_tag_size:]
        ciphertext = ciphertext[:-self.__auth_tag_size]

        decryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        authentication_new = self.__authenticate(ciphertext, ad, authentication_key)

        # Verify that both authentications are equal
        if not hmac.compare_digest(authentication_old, authentication_new):
            raise AuthenticationFailedException()

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size), CBC mode and the previously created key and iv
        plaintext = self.__getAES(decryption_key, iv).decrypt(ciphertext)
        
        # Remove the PKCS#7 padding from the plaintext and return the final unencrypted plaintext
        return Padding.unpad(plaintext, 16, "pkcs7")
