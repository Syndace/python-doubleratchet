# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
from collections import OrderedDict
import copy
import itertools
import json
from typing import Optional, Tuple, Type, TypeVar, cast

from .aead import AEAD
from .diffie_hellman_ratchet import DiffieHellmanRatchet
from .kdf import KDF
from .migrations import parse_double_ratchet_model
from .models import DoubleRatchetModel, SkippedMessageKeyModel
from .types import EncryptedMessage, Header, JSONObject, SkippedMessageKeys


__all__ = [  # pylint: disable=unused-variable
    "DoubleRatchet"
]


DoubleRatchetTypeT = TypeVar("DoubleRatchetTypeT", bound="DoubleRatchet")


class DoubleRatchet(ABC):
    """
    Combining the symmetric-key ratchet and the Diffie-Hellman ratchet gives the Double Ratchet.

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
    async def encrypt_initial_message(
        cls: Type[DoubleRatchetTypeT],
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
    ) -> Tuple[DoubleRatchetTypeT, EncryptedMessage]:
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
            A configured instance of :class:`DoubleRatchet` ready to send and receive messages together with
            the initial message.
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
        self.__diffie_hellman_ratchet = await diffie_hellman_ratchet_class.create(
            None,
            recipient_ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, header = await self.__diffie_hellman_ratchet.next_encryption_key()
        ciphertext = await self.__aead.encrypt(
            message,
            message_key,
            self._build_associated_data(associated_data, header)
        )

        return (self, EncryptedMessage(header=header, ciphertext=ciphertext))

    @classmethod
    async def decrypt_initial_message(
        cls: Type[DoubleRatchetTypeT],
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD],
        shared_secret: bytes,
        own_ratchet_priv: bytes,
        message: EncryptedMessage,
        associated_data: bytes
    ) -> Tuple[DoubleRatchetTypeT, bytes]:
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
            own_ratchet_priv: The ratchet private key to use initially.
            message: The encrypted initial message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            A configured instance of :class:`DoubleRatchet` ready to send and receive messages together with
            the decrypted initial message.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
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
        self.__aead = aead
        self.__diffie_hellman_ratchet = await diffie_hellman_ratchet_class.create(
            own_ratchet_priv,
            message.header.ratchet_pub,
            root_chain_kdf,
            shared_secret,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        message_key, skipped_message_keys = \
            await self.__diffie_hellman_ratchet.next_decryption_key(message.header)

        # Even the first message might have skipped message keys. The number of keys can't cross thresholds,
        # thus no FIFO discarding required.
        self.__skipped_message_keys = skipped_message_keys

        return (self, await self.__aead.decrypt(
            message.ciphertext,
            message_key,
            self._build_associated_data(associated_data, message.header)
        ))

    @property
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain of the internal symmetric-key ratchet, as exposed by the internal
            Diffie-Hellman ratchet.
        """

        return self.__diffie_hellman_ratchet.sending_chain_length

    @property
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain of the internal symmetric-key ratchet, if it exists, as exposed
            by the internal Diffie-Hellman ratchet.
        """

        return self.__diffie_hellman_ratchet.receiving_chain_length

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

    #################
    # serialization #
    #################

    @property
    def model(self) -> DoubleRatchetModel:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a pydantic model.
        """

        return DoubleRatchetModel(
            diffie_hellman_ratchet=self.__diffie_hellman_ratchet.model,
            skipped_message_keys=[ SkippedMessageKeyModel(
                ratchet_pub=ratchet_pub,
                index=index,
                message_key=message_key
            ) for (ratchet_pub, index), message_key in self.__skipped_message_keys.items() ]
        )

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`DoubleRatchet` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @classmethod
    def from_model(
        cls: Type[DoubleRatchetTypeT],
        model: DoubleRatchetModel,
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD]
    ) -> DoubleRatchetTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`DoubleRatchet`, as produced
                by :attr:`model`.
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
            A configured instance of :class:`DoubleRatchet`, with internal state restored from the model.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating an instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance using
                :meth:`encrypt_initial_message` or :meth:`decrypt_initial_message` without losing information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        if dos_protection_threshold > max_num_skipped_message_keys:
            raise ValueError(
                "The `dos_protection_threshold` can't be bigger than `max_num_skipped_message_keys`."
            )

        self = cls()
        self.__max_num_skipped_message_keys = max_num_skipped_message_keys
        self.__skipped_message_keys = OrderedDict(
            ((smk.ratchet_pub, smk.index), smk.message_key)
            for smk
            in model.skipped_message_keys
        )
        self.__aead = aead
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet_class.from_model(
            model.diffie_hellman_ratchet,
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

        return self

    @classmethod
    def from_json(
        cls: Type[DoubleRatchetTypeT],
        serialized: JSONObject,
        diffie_hellman_ratchet_class: Type[DiffieHellmanRatchet],
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int,
        max_num_skipped_message_keys: int,
        aead: Type[AEAD]
    ) -> DoubleRatchetTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`DoubleRatchet`, as produced by :attr:`json`.
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
            A configured instance of :class:`DoubleRatchet`, with internal state restored from the serialized
            data.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating an instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance using
                :meth:`encrypt_initial_message` or :meth:`decrypt_initial_message` without losing information.
        """

        return cls.from_model(
            parse_double_ratchet_model(serialized),
            diffie_hellman_ratchet_class,
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold,
            max_num_skipped_message_keys,
            aead
        )

    #########################
    # message en/decryption #
    #########################

    async def encrypt_message(self, message: bytes, associated_data: bytes) -> EncryptedMessage:
        """
        Args:
            message: The message to encrypt.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The encrypted message including the header to send to the recipient.
        """

        message_key, header = await self.__diffie_hellman_ratchet.next_encryption_key()
        ciphertext = await self.__aead.encrypt(
            message,
            message_key,
            self._build_associated_data(associated_data, header)
        )

        return EncryptedMessage(header=header, ciphertext=ciphertext)

    async def decrypt_message(self, message: EncryptedMessage, associated_data: bytes) -> bytes:
        """
        Args:
            message: The encrypted message.
            associated_data: Additional data to authenticate without including it in the ciphertext.

        Returns:
            The message plaintext, after decrypting and authenticating the ciphertext.

        Raises:
            AuthenticationFailedException: if the message could not be authenticated using the associated
                data.
            DecryptionFailedException: if the decryption failed for a different reason (e.g. invalid padding).
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
                first before decrypting the message.
            DuplicateMessageException: if this message appears to be a duplicate.
        """

        # Be careful to only keep changes to the internal state on decryption success. To do so, work with a
        # clone of the Diffie-Hellman ratchet, discard the clone on failure or replace the original with the
        # clone on success.
        # https://signal.org/docs/specifications/doubleratchet/#decrypting-messages

        diffie_hellman_ratchet = copy.deepcopy(self.__diffie_hellman_ratchet)
        skipped_message_keys: Optional[SkippedMessageKeys] = None
        skipped_message_key_key = (message.header.ratchet_pub, message.header.sending_chain_length)

        # Get the message key, either from the skipped message keys or from the Diffie-Hellman ratchet clone
        message_key: bytes
        try:
            message_key = self.__skipped_message_keys[skipped_message_key_key]
        except KeyError:
            message_key, skipped_message_keys = \
                await diffie_hellman_ratchet.next_decryption_key(message.header)

        # Decrypt the message (or at least attempt to do so). At this point, the internal state of this
        # instance remains untouched.
        plaintext = await self.__aead.decrypt(
            message.ciphertext,
            message_key,
            self._build_associated_data(associated_data, message.header)
        )

        # Following decryption success, apply relevant changes to the internal state.

        # In case a skipped message key was used, remove it.
        self.__skipped_message_keys.pop(skipped_message_key_key, None)

        # Store new skipped message keys and limit their number.
        if skipped_message_keys is not None:
            self.__skipped_message_keys.update(skipped_message_keys)
            self.__skipped_message_keys = OrderedDict(itertools.islice(
                self.__skipped_message_keys.items(),
                max(len(self.__skipped_message_keys) - self.__max_num_skipped_message_keys, 0),
                None
            ))

        # Store the clone.
        self.__diffie_hellman_ratchet = diffie_hellman_ratchet

        return plaintext
