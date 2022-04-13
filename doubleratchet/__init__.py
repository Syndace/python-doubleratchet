from .version import __version__
from .project import project

from .aead import AEAD, AuthenticationFailedException, DecryptionFailedException
from .diffie_hellman_ratchet import DiffieHellmanRatchet, DoSProtectionException, DuplicateMessageException
from .double_ratchet import DoubleRatchet
from .kdf import KDF
from .kdf_chain import KDFChain
from .migrations import InconsistentSerializationException
from .models import DiffieHellmanRatchetModel, DoubleRatchetModel, KDFChainModel, SymmetricKeyRatchetModel
from .symmetric_key_ratchet import Chain, ChainNotAvailableException, SymmetricKeyRatchet
from .types import EncryptedMessage, Header, JSONObject, SkippedMessageKeys


# Fun:
# https://github.com/PyCQA/pylint/issues/6006
# https://github.com/python/mypy/issues/10198
__all__ = [  # pylint: disable=unused-variable
    # .version
    "__version__",

    # .project
    "project",

    # .aead
    "AEAD",
    "AuthenticationFailedException",
    "DecryptionFailedException",

    # .diffie_hellman_ratchet
    "DiffieHellmanRatchet",
    "DoSProtectionException",
    "DuplicateMessageException",

    # .double_ratchet
    "DoubleRatchet",

    # .kdf
    "KDF",

    # .kdf_chain
    "KDFChain",

    # .migrations
    "InconsistentSerializationException",

    # .models
    "DiffieHellmanRatchetModel",
    "DoubleRatchetModel",
    "KDFChainModel",
    "SymmetricKeyRatchetModel",

    # .symmetric_key_ratchet
    "Chain",
    "ChainNotAvailableException",
    "SymmetricKeyRatchet",

    # .types
    "EncryptedMessage",
    "Header",
    "JSONObject",
    "SkippedMessageKeys"
]
