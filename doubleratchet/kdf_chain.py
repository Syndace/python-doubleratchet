from base64 import b64encode
from typing import TypeVar, Type, Dict, Union

from .kdf import KDF

from .types import (
    # Assertion Toolkit
    assert_type,
    assert_decode_base64,

    # Type Aliases
    JSONType
)

K = TypeVar("K", bound="KDFChain")
KDFChainSerialized = Dict[str, Union[int, str]]
class KDFChain:
    """
    The term KDF chain is used when some of the output from a KDF is used as an output key and some is used to
    replace the KDF key, which can then be used with another input.

    https://signal.org/docs/specifications/doubleratchet/#kdf-chains
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__kdf: Type[KDF]
        self.__key: bytes
        self.__length: int

    @classmethod
    def create(cls: Type[K], kdf: Type[KDF], key: bytes) -> K:
        # pylint: disable=protected-access
        """
        Args:
            kdf: The KDF to use for the derivation step.
            key: The initial chain key.

        Returns:
            A configured instance of :class:`~doubleratchet.kdf_chain.KDFChain`.
        """

        self = cls()
        self.__kdf    = kdf
        self.__key    = key
        self.__length = 0

        return self

    def serialize(self) -> KDFChainSerialized:
        """
        Returns:
            The internal state of this instance in a JSON-friendly serializable format. Restore the instance
            using :meth:`deserialize`.
        """

        return {
            "length" : self.__length,
            "key"    : b64encode(self.__key).decode("ASCII")
        }

    @classmethod
    def deserialize(cls: Type[K], serialized: JSONType, kdf: Type[KDF]) -> K:
        # pylint: disable=protected-access
        """
        Args:
            serialized: A serialized instance of this class, as produced by :meth:`serialize`.
            kdf: The KDF to use for the derivation step.

        Returns:
            A configured instance of :class:`~doubleratchet.kdf_chain.KDFChain` restored from the serialized
            data.

        Raises:
            TypeAssertionException: if the serialized data is structured/typed incorrectly.
        """

        root = assert_type(dict, serialized)

        self = cls()
        self.__kdf    = kdf
        self.__key    = assert_decode_base64(assert_type(str, root, "key"))
        self.__length = assert_type(int, root, "length")

        return self

    def step(self, data: bytes, length: int) -> bytes:
        """
        Perform a ratchet step of this KDF chain.

        Args:
            data: The input data.
            length: The desired size of the output data, in bytes.

        Returns:
            ``length`` bytes of output data, derived from the internal KDF key and the input data.
        """

        key_length = len(self.__key)

        output_data = self.__kdf.derive(self.__key, data, key_length + length)

        self.__length += 1
        self.__key = output_data[:key_length]

        return output_data[key_length:]

    @property
    def length(self) -> int:
        return self.__length
