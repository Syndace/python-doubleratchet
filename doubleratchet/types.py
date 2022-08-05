# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from typing import List, Mapping, NamedTuple, OrderedDict, Tuple, Union


__all__ = [  # pylint: disable=unused-variable
    "EncryptedMessage",
    "Header",
    "JSONObject",
    "SkippedMessageKeys"
]


################
# Type Aliases #
################

# # Thanks @vanburgerberg - https://github.com/python/typing/issues/182
# if TYPE_CHECKING:
#     class JSONArray(list[JSONType], Protocol):  # type: ignore
#         __class__: Type[list[JSONType]]  # type: ignore
#
#     class JSONObject(dict[str, JSONType], Protocol):  # type: ignore
#         __class__: Type[dict[str, JSONType]]  # type: ignore
#
#     JSONType = Union[None, float, int, str, bool, JSONArray, JSONObject]

# Sadly @vanburgerberg's solution doesn't seem to like Dict[str, bool], thus for now an incomplete JSON
# type with finite levels of depth.
Primitives = Union[None, float, int, str, bool]
JSONType1 = Union[Primitives, List[Primitives], Mapping[str, Primitives]]
JSONType = Union[Primitives, List[JSONType1], Mapping[str, JSONType1]]
JSONObject = Mapping[str, JSONType]

SkippedMessageKeys = OrderedDict[Tuple[bytes, int], bytes]


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
