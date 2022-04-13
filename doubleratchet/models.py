from typing import List, Optional

from pydantic import BaseModel

from .version import __version__


# BASE64 UNTIL https://github.com/samuelcolvin/pydantic/issues/3756 IS FIXED


__all__ = [  # pylint: disable=unused-variable
    "DiffieHellmanRatchetModel",
    "DoubleRatchetModel",
    "KDFChainModel",
    "SkippedMessageKeyModel",
    "SymmetricKeyRatchetModel"
]


class KDFChainModel(BaseModel):
    """
    The model representing the internal state of a :class:`~doubleratchet.kdf_chain.KDFChain`.
    """

    version: str = __version__["short"]
    length: int
    key_b64: bytes


class SymmetricKeyRatchetModel(BaseModel):
    """
    The model representing the internal state of a
    :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet`.
    """

    version: str = __version__["short"]
    receiving_chain: Optional[KDFChainModel]
    sending_chain: Optional[KDFChainModel]
    previous_sending_chain_length: Optional[int]


class DiffieHellmanRatchetModel(BaseModel):
    """
    The model representing the internal state of a
    :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
    """

    version: str = __version__["short"]
    own_ratchet_priv_b64: bytes
    other_ratchet_pub_b64: bytes
    root_chain: KDFChainModel
    symmetric_key_ratchet: SymmetricKeyRatchetModel


class SkippedMessageKeyModel(BaseModel):
    """
    The model used as part of the :class:`DoubleRatchetModel`, representing a single skipped message key with
    meta data.
    """

    ratchet_pub_b64: bytes
    index: int
    message_key_b64: bytes


class DoubleRatchetModel(BaseModel):
    """
    The model representing the internal state of a :class:`~doubleratchet.double_ratchet.DoubleRatchet`.
    """

    version: str = __version__["short"]
    diffie_hellman_ratchet: DiffieHellmanRatchetModel
    skipped_message_keys: List[SkippedMessageKeyModel]
