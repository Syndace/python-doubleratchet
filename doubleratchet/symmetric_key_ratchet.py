# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

import enum
import json
from typing import Optional, Type, TypeVar, cast
from typing_extensions import assert_never

from .kdf import KDF
from .kdf_chain import KDFChain
from .migrations import parse_symmetric_key_ratchet_model
from .models import SymmetricKeyRatchetModel
from .types import JSONObject


__all__ = [  # pylint: disable=unused-variable
    "Chain",
    "ChainNotAvailableException",
    "SymmetricKeyRatchet"
]


class ChainNotAvailableException(Exception):
    """
    Raised by :meth:`SymmetricKeyRatchet.next_encryption_key` and
    :meth:`SymmetricKeyRatchet.next_decryption_key` in case the required chain has not been initialized yet.
    """


@enum.unique
class Chain(enum.Enum):
    """
    Enumeration identifying the chain to replace by :meth:`SymmetricKeyRatchet.replace_chain`.
    """

    SENDING: str = "SENDING"
    RECEIVING: str = "RECEIVING"


SymmetricKeyRatchetTypeT = TypeVar("SymmetricKeyRatchetTypeT", bound="SymmetricKeyRatchet")


class SymmetricKeyRatchet:
    """
    The sending and receiving chains advance as each message is sent and received. Their output keys are used
    to encrypt and decrypt messages. This is called the symmetric-key ratchet.

    https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__kdf: Type[KDF]
        self.__constant: bytes
        self.__receiving_chain: Optional[KDFChain]
        self.__sending_chain: Optional[KDFChain]
        self.__previous_sending_chain_length: Optional[int]

    @classmethod
    def create(
        cls: Type[SymmetricKeyRatchetTypeT],
        chain_kdf: Type[KDF],
        constant: bytes
    ) -> SymmetricKeyRatchetTypeT:
        """
        Args:
            chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            constant: The constant to feed into the sending and receiving KDF chains on each step.

        Returns:
            A configured instance of :class:`SymmetricKeyRatchet`.
        """

        self = cls()
        self.__kdf = chain_kdf
        self.__constant = constant
        self.__receiving_chain = None
        self.__sending_chain = None
        self.__previous_sending_chain_length = None

        return self

    @property
    def model(self) -> SymmetricKeyRatchetModel:
        """
        Returns:
            The internal state of this :class:`SymmetricKeyRatchet` as a pydantic model.
        """

        return SymmetricKeyRatchetModel(
            receiving_chain=None if self.__receiving_chain is None else self.__receiving_chain.model,
            sending_chain=None if self.__sending_chain is None else self.__sending_chain.model,
            previous_sending_chain_length=self.__previous_sending_chain_length
        )

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`SymmetricKeyRatchet` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @classmethod
    def from_model(
        cls: Type[SymmetricKeyRatchetTypeT],
        model: SymmetricKeyRatchetModel,
        chain_kdf: Type[KDF],
        constant: bytes
    ) -> SymmetricKeyRatchetTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`SymmetricKeyRatchet`, as
                produced by :attr:`model`.
            chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            constant: The constant to feed into the sending and receiving KDF chains on each step.

        Returns:
            A configured instance of :class:`SymmetricKeyRatchet`, with internal state restored from the
            model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__kdf = chain_kdf
        self.__constant = constant
        self.__receiving_chain = None if model.receiving_chain is None else KDFChain.from_model(
            model.receiving_chain,
            chain_kdf
        )
        self.__sending_chain = None if model.sending_chain is None else KDFChain.from_model(
            model.sending_chain,
            chain_kdf
        )
        self.__previous_sending_chain_length = model.previous_sending_chain_length

        return self

    @classmethod
    def from_json(
        cls: Type[SymmetricKeyRatchetTypeT],
        serialized: JSONObject,
        chain_kdf: Type[KDF],
        constant: bytes
    ) -> SymmetricKeyRatchetTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`SymmetricKeyRatchet`, as produced by :attr:`json`.
            chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            constant: The constant to feed into the sending and receiving KDF chains on each step.

        Returns:
            A configured instance of :class:`SymmetricKeyRatchet`, with internal state restored from the
            serialized data.
        """

        return cls.from_model(
            parse_symmetric_key_ratchet_model(serialized),
            chain_kdf,
            constant
        )

    def replace_chain(self, chain: Chain, key: bytes) -> None:
        """
        Replace either the sending or the receiving chain with a new KDF chain.

        Args:
            chain: The chain to replace.
            key: The initial chain key for the new KDF chain.
        """

        if len(key) != 32:
            raise ValueError("The chain key must consist of 32 bytes.")

        if chain is Chain.SENDING:
            self.__previous_sending_chain_length = self.sending_chain_length
            self.__sending_chain = KDFChain.create(self.__kdf, key)
        elif chain is Chain.RECEIVING:
            self.__receiving_chain = KDFChain.create(self.__kdf, key)
        else:
            assert_never(chain)

    @property
    def previous_sending_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the previous sending chain, if it exists.
        """

        return self.__previous_sending_chain_length

    @property
    def sending_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the sending chain, if it exists.
        """

        return None if self.__sending_chain is None else self.__sending_chain.length

    @property
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain, if it exists.
        """

        return None if self.__receiving_chain is None else self.__receiving_chain.length

    async def next_encryption_key(self) -> bytes:
        """
        Returns:
            The next (32 bytes) encryption key derived from the sending chain.

        Raises:
            ChainNotAvailableException: if the sending chain was never initialized.
        """

        if self.__sending_chain is None:
            raise ChainNotAvailableException(
                "The sending chain was never initialized, can not derive the next encryption key."
            )

        return await self.__sending_chain.step(self.__constant, 32)

    async def next_decryption_key(self) -> bytes:
        """
        Returns:
            The next (32 bytes) decryption key derived from the receiving chain.

        Raises:
            ChainNotAvailableException: if the receiving chain was never initialized.
        """

        if self.__receiving_chain is None:
            raise ChainNotAvailableException(
                "The receiving chain was never initialized, can not derive the next decryption key."
            )

        return await self.__receiving_chain.step(self.__constant, 32)
