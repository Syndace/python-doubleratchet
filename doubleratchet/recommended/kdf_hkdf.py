from abc import abstractmethod

from .crypto_provider import HashFunction
from .crypto_provider_impl import CryptoProviderImpl
from .. import kdf


__all__ = [  # pylint: disable=unused-variable
    "KDF"
]


class KDF(kdf.KDF):
    """
    This KDF implemention uses HKDF with SHA-256 or SHA-512, using the KDF key as HKDF salt, the KDF data as
    HKDF input key material, and an application-specific byte sequence as HKDF info. The info value should be
    chosen to be distinct from other uses of HKDF in the application.

    https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
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
    async def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        return await CryptoProviderImpl.hkdf_derive(
            hash_function=cls._get_hash_function(),
            length=length,
            salt=key,
            info=cls._get_info(),
            key_material=data
        )
