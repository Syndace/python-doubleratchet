from typing import Any, List, Optional

from pydantic import BaseModel
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator
from typing_extensions import Annotated


__all__ = [  # pylint: disable=unused-variable
    "DiffieHellmanRatchetModel",
    "DoubleRatchetModel",
    "KDFChainModel",
    "SkippedMessageKeyModel",
    "SymmetricKeyRatchetModel"
]


def _json_bytes_decoder(val: Any) -> bytes:
    """
    Decode bytes from a string according to the JSON specification. See
    https://github.com/samuelcolvin/pydantic/issues/3756 for details.

    Args:
        val: The value to type check and decode.

    Returns:
        The value decoded to bytes. If the value is bytes already, it is returned unmodified.

    Raises:
        ValueError: if the value is not correctly encoded.
    """

    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes(map(ord, val))
    raise ValueError("bytes fields must be encoded as bytes or str.")


def _json_bytes_encoder(val: bytes) -> str:
    """
    Encode bytes as a string according to the JSON specification. See
    https://github.com/samuelcolvin/pydantic/issues/3756 for details.

    Args:
        val: The bytes to encode.

    Returns:
        The encoded bytes.
    """

    return "".join(map(chr, val))


JsonBytes = Annotated[bytes, PlainValidator(_json_bytes_decoder), PlainSerializer(_json_bytes_encoder)]


class KDFChainModel(BaseModel):
    """
    The model representing the internal state of a :class:`~doubleratchet.kdf_chain.KDFChain`.
    """

    version: str = "1.0.0"
    length: int
    key: JsonBytes


class SymmetricKeyRatchetModel(BaseModel):
    """
    The model representing the internal state of a
    :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet`.
    """

    version: str = "1.0.0"
    receiving_chain: Optional[KDFChainModel]
    sending_chain: Optional[KDFChainModel]
    previous_sending_chain_length: Optional[int]


class DiffieHellmanRatchetModel(BaseModel):
    """
    The model representing the internal state of a
    :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
    """

    version: str = "1.0.0"
    own_ratchet_priv: JsonBytes
    other_ratchet_pub: JsonBytes
    root_chain: KDFChainModel
    symmetric_key_ratchet: SymmetricKeyRatchetModel


class SkippedMessageKeyModel(BaseModel):
    """
    The model used as part of the :class:`DoubleRatchetModel`, representing a single skipped message key with
    meta data.
    """

    ratchet_pub: JsonBytes
    index: int
    message_key: JsonBytes


class DoubleRatchetModel(BaseModel):
    """
    The model representing the internal state of a :class:`~doubleratchet.double_ratchet.DoubleRatchet`.
    """

    version: str = "1.0.0"
    diffie_hellman_ratchet: DiffieHellmanRatchetModel
    skipped_message_keys: List[SkippedMessageKeyModel]
