from base64 import b64encode, b64decode
import binascii
import json
from typing import TypeVar, Type, Dict, Union, Optional, Callable, Any, NamedTuple, List, Tuple

# All TypeVars here to avoid name clashes
A = TypeVar("A")
B = TypeVar("B")
K = TypeVar("K", bound="KeyPair")

#####################
# Assertion Toolkit #
#####################

class TypeAssertionException(TypeError):
    pass

def assert_in(obj: Dict[Any, Any], key: str) -> Any:
    """
    Asserts that ``obj`` contains an element ``key`` and returns the corresponding element.

    Raises:
        TypeAssertionException: if the object does not contain the expected key.
    """

    if key not in obj:
        raise TypeAssertionException("Dictionary `{}` does not contain key `{}`.".format(obj, key))

    return obj[key]

def assert_type(expected_type: Type[A], obj: Any, key: Optional[str] = None) -> A:
    """
    Args:
        expected_type: The excpected type of ``obj``.
        obj: The object to type check.
        key: If given, the object is treated as a dictionary and ``obj[key]`` is type checked instead of
            ``obj``.

    Returns:
        The type checked and correctly typed object.

    Raises:
        TypeAssertionException: if the object is not of the expected type.
    """

    if key is not None:
        obj = assert_in(assert_type(dict, obj), key)

    if not isinstance(obj, expected_type):
        raise TypeAssertionException("Object `{}` is not of type `{}` but `{}`.".format(
            obj,
            expected_type,
            type(obj)
        ))

    return obj

def assert_type_optional(expected_type: Type[A], obj: Any, key: Optional[str] = None) -> Optional[A]:
    """
    Args:
        expected_type: The excpected type of ``obj``, if ``obj`` is not None.
        obj: The object to type check.
        key: If given, the object is treated as a dictionary and ``obj[key]`` is type checked instead of
            ``obj``.

    Returns:
        The type checked and correctly typed object.

    Raises:
        TypeAssertionException: if the object is not of the expected type.
    """

    if key is not None:
        obj = assert_in(assert_type(dict, obj), key)

    if obj is None:
        return None

    return assert_type(expected_type, obj)

def assert_decode_json(expected_type: Type[A], json_encoded: str) -> A:
    """
    Asserts that ``json_encoded`` contains valid JSON, deserializes the JSON and checks that the resulting
    object has the expected type.

    Raises:
        TypeAssertionException: if the string does not contain valid JSON or the deserialized JSON is not of
            the expected type.
    """

    try:
        return assert_type(expected_type, json.loads(json_encoded))
    except json.JSONDecodeError as e:
        raise TypeAssertionException("The string `{}` does not contain valid JSON.".format(
            json_encoded
        )) from e

def assert_decode_base64(base64_encoded: str) -> bytes:
    """
    Asserts that ``base64_encoded`` is ASCII-encodable and contains valid base64 encoded data, deserializes
    and returns it.

    Raises:
        TypeAssertionException: if the string is not ASCII-encodable or does not contain valid base64 encoded
            data.
    """

    try:
        return b64decode(base64_encoded.encode("ASCII", errors="strict"), validate=True)
    except UnicodeEncodeError as e:
        raise TypeAssertionException("The string `{}` is not ASCII-encodable.".format(
            base64_encoded
        )) from e
    except binascii.Error as e:
        raise TypeAssertionException("The string `{}` does not contain valid base64 encoded data.".format(
            base64_encoded
        )) from e

###########
# Helpers #
###########

def maybe(obj: Optional[A], func: Callable[[A], B]) -> Optional[B]:
    if obj is not None:
        return func(obj)

    return None

def maybe_or(obj: Optional[A], func: Callable[[A], B], exc: BaseException) -> B:
    if obj is not None:
        return func(obj)

    raise exc

def default(obj: Optional[A], value: A) -> A:
    return value if obj is None else obj

################
# Type Aliases #
################

# This type definition is far from optimal, but mypy doesn't support recurisve types yet (and I doubt it ever
# will).
JSONType = Union[None, bool, int, str, List[Any], Dict[str, Any]]

KeyPairSerialized = Dict[str, str]
SkippedMessageKeys = Dict[Tuple[bytes, int], bytes]
# Better: SkippedMessageKeys = OrderedDict[Tuple[bytes, int], bytes]

############################
# Structures (NamedTuples) #
############################

class Header(NamedTuple):
    ratchet_pub: bytes
    pn: int
    n: int

class EncryptedMessage(NamedTuple):
    header: Header
    ciphertext: bytes

class KeyPair(NamedTuple):
    priv: bytes
    pub: bytes

    def serialize(self) -> KeyPairSerialized:
        return {
            "priv" : b64encode(self.priv).decode("ASCII"),
            "pub"  : b64encode(self.pub).decode("ASCII")
        }

    @classmethod
    def deserialize(cls: Type[K], serialized: JSONType) -> K:
        root = assert_type(dict, serialized)

        return cls(
            priv = assert_decode_base64(assert_type(str, root, "priv")),
            pub  = assert_decode_base64(assert_type(str, root, "pub"))
        )
