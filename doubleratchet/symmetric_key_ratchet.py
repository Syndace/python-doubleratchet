import enum
from functools import partial
from typing import TypeVar, Type, Optional, Dict, Union

from .kdf import KDF
from .kdf_chain import KDFChain, KDFChainSerialized

from .types import (
    # Assertion Toolkit
    assert_in,
    assert_type,
    assert_type_optional,

    # Helpers
    maybe,
    maybe_or,

    # Type Aliases
    JSONType
)

class ChainNotAvailableException(Exception):
    pass

@enum.unique
class Chain(enum.Enum):
    Sending   : str = "Sending"
    Receiving : str = "Receiving"

S = TypeVar("S", bound="SymmetricKeyRatchet")
SymmetricKeyRatchetSerialized = Dict[str, Union[Optional[KDFChainSerialized], Optional[int]]]
class SymmetricKeyRatchet:
    """
    The sending and receiving chains advance as each message is sent and received. Their output keys are used
    to encrypt and decrypt messages. This is called the symmetric-key ratchet.

    https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__kdf: Type[KDF]

        self.__schain: Optional[KDFChain]
        self.__rchain: Optional[KDFChain]

        self.__constant: bytes

        self.__prev_schain_length: Optional[int]

    @classmethod
    def create(
        cls: Type[S],
        chain_kdf: Type[KDF],
        constant: bytes
    ) -> S:
        # pylint: disable=protected-access
        """
        Args:
            chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            constant: The constant to feed into the sending and receiving KDF chains on each step.

        Returns:
            A configured instance of :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet`.
        """

        self = cls()

        self.__kdf = chain_kdf

        self.__schain = None
        self.__rchain = None

        self.__constant = constant

        self.__prev_schain_length = None

        return self

    def serialize(self) -> SymmetricKeyRatchetSerialized:
        """
        Returns:
            The internal state of this instance in a JSON-friendly serializable format. Restore the instance
            using :meth:`deserialize`.
        """

        return {
            "schain": maybe(self.__schain, lambda x: x.serialize()),
            "rchain": maybe(self.__rchain, lambda x: x.serialize()),
            "prev_schain_length": self.__prev_schain_length
        }

    @classmethod
    def deserialize(
        cls: Type[S],
        serialized: JSONType,
        chain_kdf: Type[KDF],
        constant: bytes
    ) -> S:
        # pylint: disable=protected-access
        """
        Args:
            serialized: A serialized instance of this class, as produced by :meth:`serialize`.
            chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            constant: The constant to feed into the sending and receiving KDF chains on each step.

        Returns:
            A configured instance of :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet`
            restored from the serialized data.

        Raises:
            TypeAssertionException: if the serialized data is structured/typed incorrectly.
        """

        root = assert_type(dict, serialized)

        self = cls()

        self.__kdf = chain_kdf

        self.__schain = maybe(assert_in(root, "schain"), partial(KDFChain.deserialize, kdf=chain_kdf))
        self.__rchain = maybe(assert_in(root, "rchain"), partial(KDFChain.deserialize, kdf=chain_kdf))

        self.__constant = constant

        self.__prev_schain_length = assert_type_optional(int, root, "prev_schain_length")

        return self

    def replace_chain(self, chain: Chain, key: bytes) -> None:
        """
        Replace either the sending or the receiving chain with a new KDF chain.

        Args:
            chain: The chain to replace.
            key: The initial chain key for the new KDF chain.
        """

        if len(key) != 32:
            raise ValueError("The chain key must consist of 32 bytes.")

        if chain is Chain.Sending:
            self.__prev_schain_length = maybe(self.__schain, lambda x: x.length)
            self.__schain = KDFChain.create(self.__kdf, key)

        if chain is Chain.Receiving:
            self.__rchain = KDFChain.create(self.__kdf, key)

    @property
    def previous_sending_chain_length(self) -> Optional[int]:
        return self.__prev_schain_length

    @property
    def sending_chain_length(self) -> Optional[int]:
        return maybe(self.__schain, lambda x: x.length)

    @property
    def receiving_chain_length(self) -> Optional[int]:
        return maybe(self.__rchain, lambda x: x.length)

    def next_encryption_key(self) -> bytes:
        """
        Returns:
            The next (32 bytes) encryption key derived from the sending chain.

        Raises:
            ChainNotAvailableException: if the sending chain was never initialized.
        """

        return maybe_or(self.__schain, lambda x: x.step(self.__constant, 32), ChainNotAvailableException(
            "The sending chain was never initialized, can not derive the next encryption key."
        ))

    def next_decryption_key(self) -> bytes:
        """
        Returns:
            The next (32 bytes) decryption key derived from the receiving chain.

        Raises:
            ChainNotAvailableException: if the receiving chain was never initialized.
        """

        return maybe_or(self.__rchain, lambda x: x.step(self.__constant, 32), ChainNotAvailableException(
            "The receiving chain was never initialized, can not derive the next decryption key."
        ))
