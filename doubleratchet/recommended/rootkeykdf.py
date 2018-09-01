from __future__ import absolute_import

from ..kdf import KDF

from hkdf import hkdf_expand, hkdf_extract

import hashlib

class RootKeyKDF(KDF):
    """
    An implementations of the KDF interface based on a recommendation by WhisperSystems:

    This function is recommended to be implemented using HKDF with SHA-256 or SHA-512,
    using rk as HKDF salt, dh_out as HKDF input key material, and an application-specific
    byte sequence as HKDF info. The info value should be chosen to be distinct from other
    uses of HKDF in the application.
    """

    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(self, hash_function, info_string):
        """
        Prepare a RootKeyKDF, following a recommendation by WhisperSystems.

        :param hash_function: One of (the strings) "SHA-256" and "SHA-512".
        :param info_string: A bytes-like object encoding a string unique to this usage
            within the application.
        """

        super(RootKeyKDF, self).__init__()

        if not hash_function in RootKeyKDF.HASH_FUNCTIONS:
            raise ValueError("Invalid value passed for the hash_function parameter.")

        if not isinstance(info_string, bytes):
            raise TypeError("Wrong type passed for the info_string parameter.")

        self.__hash_function = RootKeyKDF.HASH_FUNCTIONS[hash_function]
        self.__info_string   = info_string
    
    def calculate(self, key, data, length):
        return hkdf_expand(
            hkdf_extract(key, data, self.__hash_function),
            self.__info_string,
            length,
            self.__hash_function
        )
