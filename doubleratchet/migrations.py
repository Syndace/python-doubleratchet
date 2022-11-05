# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

import base64
from typing import Dict, List, Optional, cast

from pydantic import BaseModel

from .models import (
    DiffieHellmanRatchetModel,
    DoubleRatchetModel,
    KDFChainModel,
    SkippedMessageKeyModel,
    SymmetricKeyRatchetModel
)
from .types import JSONObject


__all__ = [  # pylint: disable=unused-variable
    "InconsistentSerializationException",
    "parse_diffie_hellman_ratchet_model",
    "parse_double_ratchet_model",
    "parse_kdf_chain_model",
    "parse_symmetric_key_ratchet_model"
]


class InconsistentSerializationException(Exception):
    """
    Raised by :func:`parse_double_ratchet_model` in case data migration from pre-stable serialization format
    is performed, and the data is structurally correct, but incomplete.
    """


class PreStableSMKKeyModel(BaseModel):
    """
    The pre-stable serialization format used JSON strings for the keys of the skipped message keys dictionary.
    This model describes the structure of those key JSON strings.
    """

    pub: str
    index: int


class PreStableKeyPairModel(BaseModel):
    """
    This model describes how a key pair was serialized in pre-stable serialization format.
    """

    priv: Optional[str]
    pub: Optional[str]


class PreStableKDFChainModel(BaseModel):
    """
    This model describes how a KDF chain was serialized in pre-stable serialization format.
    """

    length: int
    key: str


class PreStableDiffieHellmanRatchetModel(BaseModel):
    """
    This model describes how Diffie-Hellman ratchet instances were serialized in pre-stable serialization
    format.
    """

    root_chain: PreStableKDFChainModel
    own_key: PreStableKeyPairModel
    other_pub: PreStableKeyPairModel


class PreStableSymmetricKeyRatchetModel(BaseModel):
    """
    This model describes how symmetric-key ratchet instances were serialized in pre-stable serialization
    format.
    """

    schain: Optional[PreStableKDFChainModel]
    rchain: Optional[PreStableKDFChainModel]
    prev_schain_length: Optional[int]


class PreStableModel(BaseModel):
    """
    This model describes how Double Ratchet instances were serialized in pre-stable serialization format.
    """

    super: PreStableDiffieHellmanRatchetModel
    skr: PreStableSymmetricKeyRatchetModel
    ad: str  # pylint: disable=invalid-name
    smks: Dict[str, str]


def parse_diffie_hellman_ratchet_model(serialized: JSONObject) -> DiffieHellmanRatchetModel:
    """
    Parse a serialized :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet` instance, as
    returned by :attr:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet.json`, into the most recent
    pydantic model available for the class. Perform migrations in case the pydantic models were updated.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet.from_model`.

    Note:
        Pre-stable data can only be migrated as a whole using :func:`parse_double_ratchet_model`.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from.
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": DiffieHellmanRatchetModel,
        "1.0.1": DiffieHellmanRatchetModel
    }[version](**serialized)

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, DiffieHellmanRatchetModel)

    return model


def parse_double_ratchet_model(serialized: JSONObject) -> DoubleRatchetModel:
    """
    Parse a serialized :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance, as returned by
    :attr:`~doubleratchet.double_ratchet.DoubleRatchet.json`, into the most recent pydantic model available
    for the class. Perform migrations in case the pydantic models were updated. Supports migration of
    pre-stable data.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~doubleratchet.double_ratchet.DoubleRatchet.from_model`.

    Raises:
        InconsistentSerializationException: if migration from pre-stable serialization format is performed,
            and the data is structurally correct, but incomplete. In pre-stable, it was possible to serialize
            instances which were not fully initialized yet. Those instances can be treated as non-existent and
            be replaced without losing information/messages.

    Note:
        The pre-stable serialization format left it up to the user to implement serialization of key
        pairs. The migration code assumes the format used by pre-stable
        `python-omemo <https://github.com/Syndace/python-omemo>`__ and will raise an exception if a
        different format was used. In that case, the custom format has to be migrated first by the user.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from. Special case: the pre-stable serialization format does not contain a version.
    version = cast(str, serialized["version"]) if "version" in serialized else None
    model: BaseModel = {
        None: PreStableModel,
        "1.0.0": DoubleRatchetModel,
        "1.0.1": DoubleRatchetModel
    }[version](**serialized)

    if isinstance(model, PreStableModel):
        # Run migrations from PreStableModel to DoubleRatchetModel
        if model.super.own_key.priv is None:
            raise InconsistentSerializationException(
                "The serialized data has no own ratchet private key set."
            )

        if model.super.other_pub.pub is None:
            raise InconsistentSerializationException(
                "The serialized data has no recipient ratchet public key set."
            )

        skipped_message_keys: List[SkippedMessageKeyModel] = []
        for key, message_key in model.smks.items():
            key_model = PreStableSMKKeyModel.parse_raw(key)
            skipped_message_keys.append(SkippedMessageKeyModel(
                ratchet_pub=base64.b64decode(key_model.pub),
                index=key_model.index,
                message_key=base64.b64decode(message_key)
            ))

        model = DoubleRatchetModel(
            diffie_hellman_ratchet=DiffieHellmanRatchetModel(
                own_ratchet_priv=base64.b64decode(model.super.own_key.priv),
                other_ratchet_pub=base64.b64decode(model.super.other_pub.pub),
                root_chain=KDFChainModel(
                    length=model.super.root_chain.length,
                    key=base64.b64decode(model.super.root_chain.key)
                ),
                symmetric_key_ratchet=SymmetricKeyRatchetModel(
                    receiving_chain=None if model.skr.rchain is None else KDFChainModel(
                        length=model.skr.rchain.length,
                        key=base64.b64decode(model.skr.rchain.key)
                    ),
                    sending_chain=None if model.skr.schain is None else KDFChainModel(
                        length=model.skr.schain.length,
                        key=base64.b64decode(model.skr.schain.key)
                    ),
                    previous_sending_chain_length=model.skr.prev_schain_length
                )
            ),
            skipped_message_keys=skipped_message_keys
        )

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, DoubleRatchetModel)

    return model


def parse_kdf_chain_model(serialized: JSONObject) -> KDFChainModel:
    """
    Parse a serialized :class:`~doubleratchet.kdf_chain.KDFChain` instance, as returned by
    :attr:`~doubleratchet.kdf_chain.KDFChain.json`, into the most recent pydantic model available for the
    class. Perform migrations in case the pydantic models were updated.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~doubleratchet.kdf_chain.KDFChain.from_model`.

    Note:
        Pre-stable data can only be migrated as a whole using :func:`parse_double_ratchet_model`.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from.
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": KDFChainModel,
        "1.0.1": KDFChainModel
    }[version](**serialized)

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, KDFChainModel)

    return model


def parse_symmetric_key_ratchet_model(serialized: JSONObject) -> SymmetricKeyRatchetModel:
    """
    Parse a serialized :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet` instance, as returned
    by :attr:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet.json`, into the most recent pydantic
    model available for the class. Perform migrations in case the pydantic models were updated.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet.from_model`.

    Note:
        Pre-stable data can only be migrated as a whole using :func:`parse_double_ratchet_model`.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from.
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": SymmetricKeyRatchetModel,
        "1.0.1": SymmetricKeyRatchetModel
    }[version](**serialized)

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, SymmetricKeyRatchetModel)

    return model
