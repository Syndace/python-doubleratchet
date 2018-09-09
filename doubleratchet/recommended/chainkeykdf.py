from __future__ import absolute_import

from ..kdf import KDF

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

class ChainKeyKDF(KDF):
    """
    An implementations of the KDF interface based on a recommendation by WhisperSystems:

    HMAC with SHA-256 or SHA-512 is recommended, using ck as the HMAC key and using
    separate constants as input (e.g. a single byte 0x01 as input to produce the message
    key, and a single byte 0x02 as input to produce the next chain key).

    Notice: Following these recommendations, the calculate method ignored both the data
    and the length parameters.
    """

    CRYPTOGRAPHY_BACKEND = default_backend()

    HASH_FUNCTIONS = {
        "SHA-256": hashes.SHA256,
        "SHA-512": hashes.SHA512
    }

    def __init__(self, hash_function, ck_constant = b"\x02", mk_constant = b"\x01"):
        """
        Prepare a ChainKeyKDF, following a recommendation by WhisperSystems.

        :param hash_function: One of (the strings) "SHA-256" and "SHA-512".
        :param ck_constant: A single byte used for derivation of the next chain key.
        :param mk_constant: A single byte used for derivation of the next message key.
        """

        super(ChainKeyKDF, self).__init__()

        if not hash_function in ChainKeyKDF.HASH_FUNCTIONS:
            raise ValueError("Invalid value passed for the hash_function parameter.")

        if not isinstance(ck_constant, bytes):
            raise TypeError("Wrong type passed for the ck_constant parameter.")

        if len(ck_constant) != 1:
            raise ValueError("Invalid value passed for the ck_constant parameter.")

        if not isinstance(mk_constant, bytes):
            raise TypeError("Wrong type passed for the mk_constant parameter.")

        if len(mk_constant) != 1:
            raise ValueError("Invalid value passed for the mk_constant parameter.")

        self.__hash_function = ChainKeyKDF.HASH_FUNCTIONS[hash_function]
        self.__ck_constant = ck_constant
        self.__mk_constant = mk_constant
    
    def calculate(self, key, data = None, length = None):
        chain_key = hmac.HMAC(
            key,
            self.__hash_function(),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

        chain_key.update(self.__ck_constant)

        message_key = hmac.HMAC(
            key,
            self.__hash_function(),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

        message_key.update(self.__mk_constant)

        return chain_key.finalize() + message_key.finalize()
