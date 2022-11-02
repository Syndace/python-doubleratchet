from abc import abstractmethod

from .crypto_provider import HashFunction
from .crypto_provider_impl import CryptoProviderImpl
from .. import kdf


__all__ = [  # pylint: disable=unused-variable
    "KDF"
]


class KDF(kdf.KDF):
    """
    This implementation uses HMAC with SHA-256 or SHA-512 to derive multiple outputs from a single KDF key.
    These outputs are concatenated and returned as a whole. The KDF key is used as the HMAC key, the KDF data
    is split into single bytes and one HMAC is calculated for each byte. For example, passing
    ``b"\\x01\\x02"`` as the KDF data results in two HMACs being calculated, one using ``b"\\x01"`` as the
    HMAC input and the other using ``b"\\x02"``. The two HMAC outputs are concatenated and returned. Note that
    the length of the output is fixed to a multiple of the HMAC digest size, based on the length of the KDF
    data.

    https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
    """

    @staticmethod
    @abstractmethod
    def _get_hash_function() -> HashFunction:
        pass

    @classmethod
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        hash_function = cls._get_hash_function()

        if length != len(data) * hash_function.hash_size:
            raise ValueError(
                "This HMAC-based KDF implementation can only derive keys that are n times as big as the byte"
                " size of the hash function digest, where n is the number of bytes in the KDF data."
            )

        result = b""

        for i in range(len(data)):
            result += await CryptoProviderImpl.hmac_calculate(key, hash_function, data[i:i + 1])

        return result
