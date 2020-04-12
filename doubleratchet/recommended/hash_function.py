import enum

from cryptography.hazmat.primitives import hashes

@enum.unique
class HashFunction(enum.Enum):
    SHA_256: str = "SHA-256"
    SHA_512: str = "SHA-512"
    SHA_512_256: str = "SHA-512-256"

    # pylint: disable=inconsistent-return-statements
    @property
    def as_cryptography(self) -> hashes.HashAlgorithm:
        if self is HashFunction.SHA_256:
            return hashes.SHA256()
        if self is HashFunction.SHA_512:
            return hashes.SHA512()
        if self is HashFunction.SHA_512_256:
            return hashes.SHA512_256()
