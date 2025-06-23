from __future__ import annotations

from typing import List, Mapping, NamedTuple, OrderedDict, Tuple, Union
from typing_extensions import TypeAlias


__all__ = [
    "EncryptedMessage",
    "Header",
    "JSONType",
    "JSONObject",
    "SkippedMessageKeys"
]


################
# Type Aliases #
################

JSONType: TypeAlias = Union[Mapping[str, "JSONType"], List["JSONType"], str, int, float, bool, None]
JSONObject: TypeAlias = Mapping[str, "JSONType"]

SkippedMessageKeys: TypeAlias = OrderedDict[Tuple[bytes, int], bytes]


############################
# Structures (NamedTuples) #
############################

class Header(NamedTuple):
    """
    The header structure sent with each Double Ratchet-encrypted message, containing the metadata to keep the
    ratchets synchronized.
    """

    ratchet_pub: bytes
    previous_sending_chain_length: int
    sending_chain_length: int


class EncryptedMessage(NamedTuple):
    """
    A Double Ratchet-encrypted message, consisting of the header and ciphertext.
    """

    header: Header
    ciphertext: bytes
