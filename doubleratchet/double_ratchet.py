from abc import ABCMeta, abstractmethod
from base64 import b64encode
from collections import OrderedDict
import copy
import itertools
from typing import cast, TypeVar, Type, Optional, Dict, Union, List, Tuple

from packaging.version import parse as parse_version

from .aead import AEAD
from .diffie_hellman_ratchet import (
    DiffieHellmanRatchet,
    DiffieHellmanRatchetSerialized,
    InconsistentSerializationException
)
from .kdf import KDF
from .kdf_chain import KDFChainSerialized
from .symmetric_key_ratchet import SymmetricKeyRatchetSerialized
from .types import (
    # Assertion Toolkit
    assert_in,
    assert_type,
    assert_type_optional,
    assert_decode_json,
    assert_decode_base64,

    # Helpers
    maybe,

    # Type Aliases
    JSONType,
    KeyPairSerialized,
    SkippedMessageKeys,

    # Structures (NamedTuples)
    Header,
    EncryptedMessage,
    KeyPair
)

from .version import __version__

D = TypeVar("D", bound="DoubleRatchet")
DoubleRatchetSerialized = Dict[str, Union[
    str,
    DiffieHellmanRatchetSerialized,
    List[Dict[str, Union[str, int]]]
]]
class DoubleRatchet(metaclass=ABCMeta):
    """
    Combining the symmetric-key and DH ratchets gives the Double Ratchet.

    https://signal.org/docs/specifications/doubleratchet/#double-ratchet

    Note:
        In this implementation, the Diffie-Hellman ratchet already manages the symmetric-key ratchet
        internally, see :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet` for details. The
        Double Ratchet class adds message en-/decryption and offers a more convenient public API that handles
        lost and out-of-order messages.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__max_num_skipped_message_keys: int
        self.__skipped_message_keys: SkippedMessageKeys
        self.__aead: Type[AEAD]
        self.__diffie_hellman_ratchet: DiffieHellmanRatchet

    @classmethod
    def encrypt_initial_message(
        cls: Type[D],
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD],
        shared_secret: bytes,
        recipient_ratchet_pub: bytes,
        message: bytes,
        associated_data: bytes
    ) -> Tuple[D, EncryptedMessage]:
        # pylint: disable=protected-access
        """
        Args:
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.
            shared_secret: A shared secret consisting of 32 bytes that was agreed on by means external to this
                protocol.
            recipient_ratchet_pub: The ratchet public key of the recipient.
            message: The initial message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            A configured instance of :class:`~doubleratchet.double_ratchet.DoubleRatchet` ready to send and
            receive messages together with the initial message.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        if len(shared_secret) != 32:
            raise ValueError("The shared secret must consist of 32 bytes.")

        self = cls()

        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = OrderedDict()
        self.__aead = aead
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet_class.create(
            None,
            recipient_ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, header = self.__diffie_hellman_ratchet.next_encryption_key()
        ciphertext  = self.__aead.encrypt(
            message,
            message_key,
            self._build_associated_data(associated_data, header)
        )

        return (self, EncryptedMessage(header=header, ciphertext=ciphertext))

    @classmethod
    def decrypt_initial_message(
        cls: Type[D],
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD],
        shared_secret: bytes,
        own_ratchet_key_pair: KeyPair,
        message: EncryptedMessage,
        associated_data: bytes
    ) -> Tuple[D, bytes]:
        # pylint: disable=protected-access
        """
        Args:
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.
            shared_secret: A shared secret that was agreed on by means external to this protocol.
            own_ratchet_key_pair: The ratchet key pair to use initially.
            message: The encrypted initial message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            A configured instance of :class:`~doubleratchet.double_ratchet.DoubleRatchet` ready to send and
            receive messages together with the decrypted initial message.

        Raises:
            AuthenticationFailedException: If the message could not be authenticated using the associated
                data.
            DecryptionFailedException: If the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: If a huge number of message keys were skipped that have to be calculated
                first before decrypting the message.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        if len(shared_secret) != 32:
            raise ValueError("The shared secret must consist of 32 bytes.")

        self = cls()

        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = OrderedDict()
        self.__aead = aead
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet_class.create(
            own_ratchet_key_pair,
            message.header.ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, _ = self.__diffie_hellman_ratchet.next_decryption_key(message.header)

        return (self, self.__aead.decrypt(
            message.ciphertext,
            message_key,
            self._build_associated_data(associated_data, message.header)
        ))

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        """
        Args:
            associated_data: The associated data to prepend to the output. If the associated data is not
                guaranteed to be a parseable byte sequence, a length value should be prepended to ensure that
                the output is parseable as a unique pair (associated data, header).
            header: The message header to encode in a unique, reversible manner.

        Returns:
            A byte sequence encoding the associated data and the header in a unique, reversible way.
        """

        raise NotImplementedError(
            "Create a subclass of DoubleRatchet and implement `_build_associated_data`."
        )

    #################
    # serialization #
    #################

    def serialize(self) -> DoubleRatchetSerialized:
        """
        Returns:
            The internal state of this instance in a JSON-friendly serializable format. Restore the instance
            using :meth:`deserialize`.
        """

        return {
            "diffie_hellman_ratchet" : self.__diffie_hellman_ratchet.serialize(),
            "skipped_message_keys"   : [ {
                "ratchet_pub" : b64encode(ratchet_pub).decode("ASCII"),
                "index"       : index,
                "message_key" : b64encode(message_key).decode("ASCII")
            } for (ratchet_pub, index), message_key in self.__skipped_message_keys.items() ],
            "version": __version__["short"]
        }

    @classmethod
    def deserialize(
        cls: Type[D],
        serialized: JSONType,
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD]
    ) -> D:
        # pylint: disable=protected-access
        # pylint: disable=too-many-locals
        """
        Args:
            serialized: A serialized instance of this class, as produced by :meth:`serialize`.
            diffie_hellman_ratchet_class: A non-abstract subclass of
                :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.
            max_num_skipped_message_keys: The maximum number of skipped message keys to store in case the lost
                or out-of-order message comes in later. Older keys are discarded to make space for newer keys.
            aead: The AEAD implementation to use for message en- and decryption.

        Returns:
            A configured instance of :class:`~doubleratchet.double_ratchet.DoubleRatchet` restored from the
            serialized data.

        Raises:
            InconsistentSerializationException: if the serialized data does not contain an initialized sending
                chain. This can only happen when migrating from pre-stable data a DoubleRatchet that was
                serialized before sending or receiving a single message. In this case, the serialized
                DoubleRatchet is basically uninitialized and can be discarded/replaced with a new instance
                using :meth:`encrypt_initial_message` or :meth:`decrypt_initial_message`.
            TypeAssertionException: if the serialized data is structured/typed incorrectly.

        Note:
            The pre-stable serialization format left it up to the user to implement serialization of key
            pairs. The migration code assumes the format used by pre-stable
            `python-omemo <https://github.com/Syndace/python-omemo>`_ and will raise an exception if a
            different format was used. In that case, the custom format has to be migrated first by the user.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        # All serialization formats use a dictionary as the root element.
        root = assert_type(dict, serialized)

        # If the version is included, parse it. Otherwise, assume 0.0.0 for the version.
        version = parse_version("0.0.0")
        if "version" in root:
            version = parse_version(assert_type(str, root, "version"))

        # Run migrations
        version_1_0_0 = parse_version("1.0.0")
        if version < version_1_0_0:
            # Migrate pre-stable serialization format
            root_super = assert_type(dict, root, "super")
            root_skr   = assert_type(dict, root, "skr")
            root_smks  = assert_type(dict, root, "smks")

            root_super_root_chain = assert_type(dict, root_super, "root_chain")
            root_super_own_key    = assert_type(dict, root_super, "own_key")
            root_super_other_pub  = assert_type(dict, root_super, "other_pub")

            root_skr_schain = assert_type_optional(dict, root_skr, "schain")
            root_skr_rchain = assert_type_optional(dict, root_skr, "rchain")

            schain: Optional[KDFChainSerialized] = maybe(root_skr_schain, lambda x: cast(KDFChainSerialized, {
                "length" : assert_type(int, x, "length"),
                "key"    : assert_type(str, x, "key")
            }))

            rchain: Optional[KDFChainSerialized] = maybe(root_skr_rchain, lambda x: cast(KDFChainSerialized, {
                "length" : assert_type(int, x, "length"),
                "key"    : assert_type(str, x, "key")
            }))

            ratchet_key_pair: KeyPairSerialized = {
                "priv" : assert_type(str, root_super_own_key, "priv"),
                "pub"  : assert_type(str, root_super_own_key, "pub")
            }

            root_chain: KDFChainSerialized = {
                "length" : assert_type(int, root_super_root_chain, "length"),
                "key"    : assert_type(str, root_super_root_chain, "key")
            }

            symmetric_key_ratchet: SymmetricKeyRatchetSerialized = {
                "rchain": rchain,
                "schain": schain,
                "prev_schain_length": assert_type_optional(int, root_skr, "prev_schain_length")
            }

            root_super_other_pub_pub = assert_type_optional(str, root_super_other_pub, "pub")
            if root_super_other_pub_pub is None:
                raise InconsistentSerializationException(
                    "The serialized data has no recipient ratchet public key set."
                )

            diffie_hellman_ratchet_migrated: DiffieHellmanRatchetSerialized = {
                "ratchet_key_pair"      : ratchet_key_pair,
                "other_ratchet_pub"     : root_super_other_pub_pub,
                "root_chain"            : root_chain,
                "symmetric_key_ratchet" : symmetric_key_ratchet
            }

            skipped_message_keys_migrated: List[Dict[str, Union[str, int]]] = []

            for key_encoded_untyped in root_smks:
                key_encoded = assert_type(str, key_encoded_untyped)

                key = assert_decode_json(dict, key_encoded)

                skipped_message_keys_migrated.append({
                    "ratchet_pub" : assert_type(str, key,  "pub"),
                    "index"       : assert_type(int, key,  "index"),
                    "message_key" : assert_type(str, root_smks, key_encoded)
                })

            double_ratchet_migrated: DoubleRatchetSerialized = {
                "diffie_hellman_ratchet" : diffie_hellman_ratchet_migrated,
                "skipped_message_keys"   : skipped_message_keys_migrated,
                "version": "1.0.0"
            }

            root = double_ratchet_migrated

            version = version_1_0_0

        # All migrations done, deserialize the data.
        serialized_diffie_hellman_ratchet = assert_in(root, "diffie_hellman_ratchet")
        serialized_skipped_message_keys   = assert_type(list, root, "skipped_message_keys")

        skipped_message_keys: SkippedMessageKeys = OrderedDict()

        for serialized_skipped_message_key_untyped in serialized_skipped_message_keys:
            serialized_skipped_message_key = assert_type(dict, serialized_skipped_message_key_untyped)
            serialized_ratchet_pub = assert_type(str, serialized_skipped_message_key, "ratchet_pub")
            serialized_message_key = assert_type(str, serialized_skipped_message_key, "message_key")

            ratchet_pub = assert_decode_base64(serialized_ratchet_pub)
            index       = assert_type(int, serialized_skipped_message_key, "index")
            message_key = assert_decode_base64(serialized_message_key)

            skipped_message_keys[(ratchet_pub, index)] = message_key

        self = cls()

        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = skipped_message_keys
        self.__aead = aead
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet_class.deserialize(
            serialized_diffie_hellman_ratchet,
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        return self

    #########################
    # message en/decryption #
    #########################

    def encrypt_message(self, message: bytes, associated_data: bytes) -> EncryptedMessage:
        """
        Args:
            message: The message to encrypt.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The encrypted message including the header to send to the recipient.
        """

        message_key, header = self.__diffie_hellman_ratchet.next_encryption_key()
        ciphertext  = self.__aead.encrypt(
            message,
            message_key,
            self._build_associated_data(associated_data, header)
        )

        return EncryptedMessage(header=header, ciphertext=ciphertext)

    def decrypt_message(self, message: EncryptedMessage, associated_data: bytes) -> bytes:
        """
        Args:
            message: The encrypted message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The message plaintext, after decrypting and authenticating the ciphertext.

        Raises:
            AuthenticationFailedException: If the message could not be authenticated using the associated
                data.
            DecryptionFailedException: If the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: If a huge number of message keys were skipped that have to be calculated
                first before decrypting the message.
            DuplicateMessageException: If this message appears to be a duplicate.
        """

        # If an exception is raised (e.g. message authentication failure) then the message is discarded and
        # changes to the state object are discarded. Otherwise, the decrypted plaintext is accepted and
        # changes to the state object are stored.
        # https://signal.org/docs/specifications/doubleratchet/#decrypting-messages

        # Create a clone to perform the decryption
        # pylint: disable=protected-access
        clone = copy.deepcopy(self)

        # Try to decrypt the message using the clone
        plaintext = clone.__decrypt_message(message, associated_data)

        # If the decryption didn't raise any exceptions, apply the changes in the state of the clone to self
        self.__skipped_message_keys   = clone.__skipped_message_keys
        self.__diffie_hellman_ratchet = clone.__diffie_hellman_ratchet

        return plaintext

    def __decrypt_message(self, message: EncryptedMessage, associated_data: bytes) -> bytes:
        message_key = self.__get_skipped_message_key(message.header)
        if message_key is None:
            message_key, skipped_mks = self.__diffie_hellman_ratchet.next_decryption_key(message.header)

            self.__store_skipped_message_keys(skipped_mks)

        return self.__aead.decrypt(
            message.ciphertext,
            message_key,
            self._build_associated_data(associated_data, message.header)
        )

    def __get_skipped_message_key(self, header: Header) -> Optional[bytes]:
        return self.__skipped_message_keys.pop((header.ratchet_pub, header.n), None)

    def __store_skipped_message_keys(self, skipped_message_keys: SkippedMessageKeys) -> None:
        self.__skipped_message_keys.update(skipped_message_keys)
        self.__skipped_message_keys = OrderedDict(itertools.islice(
            self.__skipped_message_keys.items(),
            max(len(self.__skipped_message_keys) - self.__max_num_skipped_message_keys, 0),
            None
        ))
