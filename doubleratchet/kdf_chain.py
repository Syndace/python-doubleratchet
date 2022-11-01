# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

import json
from typing import Type, TypeVar, cast

from .kdf import KDF
from .migrations import parse_kdf_chain_model
from .models import KDFChainModel
from .types import JSONObject


__all__ = [  # pylint: disable=unused-variable
    "KDFChain"
]


KDFChainTypeT = TypeVar("KDFChainTypeT", bound="KDFChain")


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
    def create(cls: Type[KDFChainTypeT], kdf: Type[KDF], key: bytes) -> KDFChainTypeT:
        """
        Args:
            kdf: The KDF to use for the derivation step.
            key: The initial chain key.

        Returns:
            A configured instance of :class:`KDFChain`.
        """

        self = cls()
        self.__kdf = kdf
        self.__key = key
        self.__length = 0

        return self

    @property
    def model(self) -> KDFChainModel:
        """
        Returns:
            The internal state of this :class:`KDFChain` as a pydantic model.
        """

        return KDFChainModel(length=self.__length, key=self.__key)

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`KDFChain` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @classmethod
    def from_model(cls: Type[KDFChainTypeT], model: KDFChainModel, kdf: Type[KDF]) -> KDFChainTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`KDFChain`, as produced by
                :attr:`model`.
            kdf: The KDF to use for the derivation step.

        Returns:
            A configured instance of :class:`KDFChain`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__kdf = kdf
        self.__key = model.key
        self.__length = model.length

        return self

    @classmethod
    def from_json(cls: Type[KDFChainTypeT], serialized: JSONObject, kdf: Type[KDF]) -> KDFChainTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a :class:`KDFChain`,
                as produced by :attr:`json`.
            kdf: The KDF to use for the derivation step.

        Returns:
            A configured instance of :class:`KDFChain`, with internal state restored from the serialized data.
        """

        return cls.from_model(parse_kdf_chain_model(serialized), kdf)

    async def step(self, data: bytes, length: int) -> bytes:
        """
        Perform a ratchet step of this KDF chain.

        Args:
            data: The input data.
            length: The desired size of the output data, in bytes.

        Returns:
            ``length`` bytes of output data, derived from the internal KDF key and the input data.
        """

        key_length = len(self.__key)

        output_data = await self.__kdf.derive(self.__key, data, key_length + length)

        self.__length += 1
        self.__key = output_data[:key_length]

        return output_data[key_length:]

    @property
    def length(self) -> int:
        """
        Returns:
            The length of this KDF chain, i.e. the number of steps that have been performed.
        """

        return self.__length
