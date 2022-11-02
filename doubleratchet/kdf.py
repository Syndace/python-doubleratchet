from abc import ABC, abstractmethod


__all__ = [  # pylint: disable=unused-variable
    "KDF"
]


class KDF(ABC):
    """
    A KDF is defined as a cryptographic function that takes a secret and random KDF key and some input data
    and returns output data. The output data is indistinguishable from random provided the key isn't known
    (i.e. a KDF satisfies the requirements of a cryptographic "PRF"). If the key is not secret and random, the
    KDF should still provide a secure cryptographic hash of its key and input data.

    https://signal.org/docs/specifications/doubleratchet/#kdf-chains
    """

    @staticmethod
    @abstractmethod
    async def derive(key: bytes, data: bytes, length: int) -> bytes:
        """
        Args:
            key: The KDF key.
            data: The input data.
            length: The desired size of the output data, in bytes.

        Returns:
            ``length`` bytes of output data, derived from the KDF key and the input data.
        """
