from browser import window  # type: ignore[import]  # pylint: disable=import-error
from typing_extensions import assert_never

from .crypto_provider import CryptoProvider, HashFunction


__all__ = [  # pylint: disable=unused-variable
    "CryptoProviderImpl"
]


def get_hash_name(hash_function: HashFunction) -> str:
    """
    Args:
        hash_function: Identifier of a hash function.

    Returns:
        The name of the hash function as required by the JavaScript SubtleCrypto APIs.
    """

    if hash_function is HashFunction.SHA_256:
        return "SHA-256"
    if hash_function is HashFunction.SHA_512:
        return "SHA-512"
    if hash_function is HashFunction.SHA_512_256:
        raise ValueError("Truncated SHA-512 is not supported by the Brython cryptography provider.")

    return assert_never(hash_function)


class CryptoProviderImpl(CryptoProvider):
    """
    Cryptography provider implementation based on JavaScript's SubtleCrypto API for usage with Brython.
    """

    @staticmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        return bytes(window.Array["from"](await window.crypto.subtle.exportKey(
            "raw",
            await window.crypto.subtle.deriveKey(
                {
                    "name": "HKDF",
                    "hash": get_hash_name(hash_function),
                    "salt": window.Uint8Array["from"](list(salt)),
                    "info": window.Uint8Array["from"](list(info))
                },
                await window.crypto.subtle.importKey(
                    "raw",
                    window.Uint8Array["from"](list(key_material)),
                    "HKDF",
                    False,
                    [ "deriveKey" ]
                ),
                {
                    # We have to define "the algorithm the derived key will be used for" here. This is a bit
                    # weird, since the choice of the algorithm should not influence the HKDF derivation
                    # whatsoever. Probably an attempt at "user-friendliness" by the API designers. Anyway,
                    # specifying HMAC here allows us to choose the bit size of the derived key.
                    "name": "HMAC",
                    "hash": get_hash_name(hash_function),
                    "length": length * 8
                },
                True,
                []
            )
        )))

    @staticmethod
    async def hmac_calculate(key: bytes, hash_function: HashFunction, data: bytes) -> bytes:
        return bytes(window.Array["from"](await window.crypto.subtle.sign(
            "HMAC",
            await window.crypto.subtle.importKey(
                "raw",
                window.Uint8Array["from"](list(key)),
                {
                    "name": "HMAC",
                    "hash": get_hash_name(hash_function)
                },
                False,
                [ "sign" ]
            ),
            window.Uint8Array["from"](list(data))
        )))

    @staticmethod
    async def aes_cbc_encrypt(key: bytes, initialization_vector: bytes, plaintext: bytes) -> bytes:
        return bytes(window.Array["from"](await window.crypto.subtle.encrypt(
            {
                "name": "AES-CBC",
                "iv": window.Uint8Array["from"](list(initialization_vector))
            },
            await window.crypto.subtle.importKey(
                "raw",
                window.Uint8Array["from"](list(key)),
                "AES-CBC",
                False,
                [ "encrypt" ]
            ),
            window.Uint8Array["from"](list(plaintext))
        )))

    @staticmethod
    async def aes_cbc_decrypt(key: bytes, initialization_vector: bytes, ciphertext: bytes) -> bytes:
        return bytes(window.Array["from"](await window.crypto.subtle.decrypt(
            {
                "name": "AES-CBC",
                "iv": window.Uint8Array["from"](list(initialization_vector))
            },
            await window.crypto.subtle.importKey(
                "raw",
                window.Uint8Array["from"](list(key)),
                "AES-CBC",
                False,
                [ "decrypt" ]
            ),
            window.Uint8Array["from"](list(ciphertext))
        )))
