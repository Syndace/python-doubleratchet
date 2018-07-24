from __future__ import absolute_import

from ..kdf import KDF

import hashlib
import hmac

class ChainKeyKDF(KDF):
    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(self, hash_function, chain_key_constant, message_key_constant):
        """
        The hash function parameter must be a key of ChainKeyKDF.HASH_FUNCTIONS
        ("SHA-256" or "SHA-512").

        The constants should be single bytes for each type of calculation
        (e.g. 0x01 as input to produce the message key, and a single byte 0x02 as input
        to produce the next chain key)
        """

        super(ChainKeyKDF, self).__init__()

        self.__hash_function = ChainKeyKDF.HASH_FUNCTIONS[hash_function]
        self.__chain_key_constant = chain_key_constant
        self.__message_key_constant = message_key_constant
    
    def calculate(self, key, data, length):
        """
        As recommended, use HMAC with either SHA-256 or SHA-512.
        Supply the chain key as the HMAC key and a constant as input.

        Ignore the data.
        """

        chain_key   = hmac.new(key, self.__chain_key_constant,   self.__hash_function)
        message_key = hmac.new(key, self.__message_key_constant, self.__hash_function)

        return chain_key.digest() + message_key.digest()
