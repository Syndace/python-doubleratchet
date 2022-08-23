import enum
from typing_extensions import assert_never

from cryptography.hazmat.primitives import hashes


__all__ = [  # pylint: disable=unused-variable
    "HashFunction"
]


@enum.unique
class HashFunction(enum.Enum):
    """
    Enumeration of the three hash functions that can be used with
    :class:`doubleratchet.recommended.aead_aes_hmac.AEAD`, :class:`doubleratchet.recommended.kdf_hkdf.KDF` and
    :class:`doubleratchet.recommended.kdf_separate_hmacs.KDF`. The three hash functions are SHA-256, SHA-512,
    and truncated SHA-512 to 256 bits.
    """

    SHA_256: str = "SHA_256"
    SHA_512: str = "SHA_512"
    SHA_512_256: str = "SHA_512_256"

    @property
    def as_cryptography(self) -> hashes.HashAlgorithm:
        """
        Returns:
            The implementation of the hash function as a cryptography `HashAlgorithm` object.
        """

        if self is HashFunction.SHA_256:
            return hashes.SHA256()
        if self is HashFunction.SHA_512:
            return hashes.SHA512()
        if self is HashFunction.SHA_512_256:
            return hashes.SHA512_256()

        return assert_never(self)
