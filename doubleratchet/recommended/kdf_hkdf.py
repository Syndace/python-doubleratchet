from abc import abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .hash_function import HashFunction
from .. import kdf

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
        raise NotImplementedError("Create a subclass and override `_get_hash_function`.")

    @staticmethod
    @abstractmethod
    def _get_info() -> bytes:
        raise NotImplementedError("Create a subclass and override `_get_info`.")

    @classmethod
    def derive(cls, key: bytes, data: bytes, length: int) -> bytes:
        return HKDF(
            algorithm = cls._get_hash_function().as_cryptography,
            length    = length,
            salt      = key,
            info      = cls._get_info(),
            backend   = default_backend()
        ).derive(data)