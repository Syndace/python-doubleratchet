# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
from collections import OrderedDict
import json
from typing import Optional, Tuple, Type, TypeVar, cast
import warnings

from .kdf import KDF
from .kdf_chain import KDFChain
from .migrations import InconsistentSerializationException, parse_diffie_hellman_ratchet_model
from .models import DiffieHellmanRatchetModel
from .symmetric_key_ratchet import Chain, SymmetricKeyRatchet
from .types import Header, JSONObject, SkippedMessageKeys


__all__ = [  # pylint: disable=unused-variable
    "DiffieHellmanRatchet",
    "DoSProtectionException",
    "DuplicateMessageException"
]


class DoSProtectionException(Exception):
    """
    Raised by :meth:`DiffieHellmanRatchet.next_decryption_key` in case the number of skipped message keys to
    calculate crosses the DoS protection threshold.
    """


class DuplicateMessageException(Exception):
    """
    Raised by :meth:`DiffieHellmanRatchet.next_decryption_key` in case is seems the message was processed
    before.
    """


DiffieHellmanRatchetTypeT = TypeVar("DiffieHellmanRatchetTypeT", bound="DiffieHellmanRatchet")


class DiffieHellmanRatchet(ABC):
    """
    As communication partners exchange messages they also exchange new Diffie-Hellman public keys, and the
    Diffie-Hellman output secrets become the inputs to the root chain. The output keys from the root chain
    become new KDF keys for the sending and receiving chains. This is called the Diffie-Hellman ratchet.

    https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet

    Note:
        The specification introduces the symmetric-key ratchet and the Diffie-Hellman ratchet as independent
        units and links them together in the Double Ratchet. This implementation does not follow that
        separation, instead the Diffie-Hellman ratchet manages the symmetric-key ratchet internally, which
        makes the code a little less complicated, as the Double Ratchet doesn't have to forward keys generated
        by the Diffie-Hellman ratchet to the symmetric-key ratchet.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__own_ratchet_priv: bytes
        self.__other_ratchet_pub: bytes
        self.__root_chain: KDFChain
        self.__dos_protection_threshold: int
        self.__symmetric_key_ratchet: SymmetricKeyRatchet

    @classmethod
    async def create(
        cls: Type[DiffieHellmanRatchetTypeT],
        own_ratchet_priv: Optional[bytes],
        other_ratchet_pub: bytes,
        root_chain_kdf: Type[KDF],
        root_chain_key: bytes,
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int
    ) -> DiffieHellmanRatchetTypeT:
        """
        Create and configure a Diffie-Hellman ratchet.

        Args:
            own_ratchet_priv: The ratchet private key to use initially with this instance.
            other_ratchet_pub: The ratchet public key of the other party.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            root_chain_key: The key to initialize the root chain with, consisting of 32 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, capable of sending and receiving messages.
        """

        if len(root_chain_key) != 32:
            raise ValueError("The initial key for the root chain must consist of 32 bytes.")

        self = cls()
        self.__root_chain = KDFChain.create(root_chain_kdf, root_chain_key)
        self.__dos_protection_threshold = dos_protection_threshold
        self.__symmetric_key_ratchet = SymmetricKeyRatchet.create(message_chain_kdf, message_chain_constant)

        if own_ratchet_priv is None:
            self.__own_ratchet_priv = self._generate_priv()
            self.__other_ratchet_pub = other_ratchet_pub
            await self.__replace_chain(Chain.SENDING)
        else:
            self.__own_ratchet_priv = own_ratchet_priv
            self.__other_ratchet_pub = other_ratchet_pub
            await self.__replace_chain(Chain.RECEIVING)
            self.__own_ratchet_priv = self._generate_priv()
            await self.__replace_chain(Chain.SENDING)

        return self

    @property
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain of the internal symmetric-key ratchet.
        """

        # Sanity check; the sending chain must exist
        assert self.__symmetric_key_ratchet.sending_chain_length is not None
        return self.__symmetric_key_ratchet.sending_chain_length

    @property
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain of the internal symmetric-key ratchet, if it exists.
        """

        return self.__symmetric_key_ratchet.receiving_chain_length

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _generate_priv() -> bytes:
        """
        Returns:
            A freshly generated private key, capable of performing Diffie-Hellman key exchanges with the
            public key of another party.

        Note:
            This function is recommended to generate a key pair based on the Curve25519 or Curve448 elliptic
            curves
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

    @staticmethod
    @abstractmethod
    def _derive_pub(priv: bytes) -> bytes:
        """
        Derive the public key from a private key as generated by :meth:`_generate_priv`.

        Args:
            priv: The private key as returned by :meth:`_generate_priv`.

        Returns:
            The public key corresponding to the private key.
        """

    @staticmethod
    @abstractmethod
    def _perform_diffie_hellman(own_priv: bytes, other_pub: bytes) -> bytes:
        """
        Args:
            own_priv: The own ratchet private key.
            other_pub: The ratchet public key of the other party.

        Returns:
            A shared secret agreed on via Diffie-Hellman. This method is recommended to perform X25519 or
            X448. There is no need to check for invalid public keys
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

    #################
    # serialization #
    #################

    @property
    def model(self) -> DiffieHellmanRatchetModel:
        """
        Returns:
            The internal state of this :class:`DiffieHellmanRatchet` as a pydantic model.
        """

        return DiffieHellmanRatchetModel(
            own_ratchet_priv=self.__own_ratchet_priv,
            other_ratchet_pub=self.__other_ratchet_pub,
            root_chain=self.__root_chain.model,
            symmetric_key_ratchet=self.__symmetric_key_ratchet.model
        )

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`DiffieHellmanRatchet` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @classmethod
    def from_model(
        cls: Type[DiffieHellmanRatchetTypeT],
        model: DiffieHellmanRatchetModel,
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int
    ) -> DiffieHellmanRatchetTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`DiffieHellmanRatchet`, as
                produced by :attr:`model`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, with internal state restored from the
            model.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating a
                :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance without losing
                information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__own_ratchet_priv = model.own_ratchet_priv
        self.__other_ratchet_pub = model.other_ratchet_pub
        self.__root_chain = KDFChain.from_model(model.root_chain, root_chain_kdf)
        self.__dos_protection_threshold = dos_protection_threshold
        self.__symmetric_key_ratchet = SymmetricKeyRatchet.from_model(
            model.symmetric_key_ratchet,
            message_chain_kdf,
            message_chain_constant
        )

        if self.__symmetric_key_ratchet.sending_chain_length is None:
            raise InconsistentSerializationException(
                "The restored internal state does not contain an initialized sending chain."
            )

        return self

    @classmethod
    def from_json(
        cls: Type[DiffieHellmanRatchetTypeT],
        serialized: JSONObject,
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int
    ) -> DiffieHellmanRatchetTypeT:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`DiffieHellmanRatchet`, as produced by :attr:`json`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.

        Returns:
            A configured instance of :class:`DiffieHellmanRatchet`, with internal state restored from the
            serialized data.

        Raises:
            InconsistentSerializationException: if the serialized data is structurally correct, but
                incomplete. This can only happen when migrating a
                :class:`~doubleratchet.double_ratchet.DoubleRatchet` instance from pre-stable data that was
                serialized before sending or receiving a single message. In this case, the serialized instance
                is basically uninitialized and can be discarded/replaced with a new instance without losing
                information.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        return cls.from_model(
            parse_diffie_hellman_ratchet_model(serialized),
            root_chain_kdf,
            message_chain_kdf,
            message_chain_constant,
            dos_protection_threshold
        )

    ######################
    # ratchet management #
    ######################

    async def __replace_chain(self, chain: Chain) -> None:
        """
        Replace one of the chains of the internal symmetric-key ratchet. The chain key is derived by feeding
        the Diffie-Hellman shared secret to the root chain.

        Args:
            chain: The chain to replace.
        """

        self.__symmetric_key_ratchet.replace_chain(chain, await self.__root_chain.step(
            self._perform_diffie_hellman(self.__own_ratchet_priv, self.__other_ratchet_pub),
            32
        ))

    async def next_encryption_key(self) -> Tuple[bytes, Header]:
        """
        Returns:
            The next (32 bytes) encryption key derived from the sending chain and the corresponding
            Diffie-Hellman ratchet header.
        """

        sending_chain_length = self.__symmetric_key_ratchet.sending_chain_length
        assert sending_chain_length is not None  # sanity check

        previous_sending_chain_length = self.__symmetric_key_ratchet.previous_sending_chain_length or 0

        header = Header(
            ratchet_pub=self._derive_pub(self.__own_ratchet_priv),
            previous_sending_chain_length=previous_sending_chain_length,
            sending_chain_length=sending_chain_length
        )

        next_encryption_key = await self.__symmetric_key_ratchet.next_encryption_key()

        return next_encryption_key, header

    async def next_decryption_key(self, header: Header) -> Tuple[bytes, SkippedMessageKeys]:
        """
        Args:
            header: The Diffie-Hellman ratchet header,

        Returns:
            The next (32 bytes) decryption key derived from the receiving chain and message keys that were
            skipped while deriving the new decryption key.

        Raises:
            DoSProtectionException: if a huge number of message keys were skipped that have to be calculated
                first before decrypting the next message.
            DuplicateMessageException: if this message appears to be a duplicate.
        """

        skipped_message_keys: SkippedMessageKeys = OrderedDict()

        # Perform a ratchet step if the ratchet public keys differ
        if header.ratchet_pub != self.__other_ratchet_pub:
            # If there is a receiving chain, calculate skipped message keys before replacing the chain
            receiving_chain_length = self.__symmetric_key_ratchet.receiving_chain_length
            if receiving_chain_length is not None:
                # Check whether the number of skipped message keys is within reasonable bounds
                num_skipped_keys = max(header.previous_sending_chain_length - receiving_chain_length, 0)
                if num_skipped_keys > self.__dos_protection_threshold:
                    # This is a warning rather than an exception, to make sure that in case of heavy message
                    # loss, the ratchet is not fully blocked from moving forward/"recovering" through a
                    # ratchet step.
                    warnings.warn(
                        f"More than {self.__dos_protection_threshold} message keys skipped. Not calculating"
                        " all of these message keys to prevent being DoSed."
                    )
                else:
                    # Calculate the skipped message keys
                    for _ in range(num_skipped_keys):
                        skipped_message_keys[(self.__other_ratchet_pub, receiving_chain_length)] = \
                            await self.__symmetric_key_ratchet.next_decryption_key()
                        receiving_chain_length += 1

            # Perform one full ratchet step, by replacing both the receiving and the sending chains
            self.__other_ratchet_pub = header.ratchet_pub
            await self.__replace_chain(Chain.RECEIVING)
            self.__own_ratchet_priv = self._generate_priv()
            await self.__replace_chain(Chain.SENDING)

        # Once the chains are prepared, forward the receiving chain to the required key
        receiving_chain_length = self.__symmetric_key_ratchet.receiving_chain_length
        assert receiving_chain_length is not None  # sanity check

        # Check whether the number of skipped message keys is within reasonable bounds
        num_skipped_keys = max(header.sending_chain_length - receiving_chain_length, 0)
        if num_skipped_keys > self.__dos_protection_threshold:
            raise DoSProtectionException(
                f"More than {self.__dos_protection_threshold} message keys skipped. Not calculating all of"
                " these message keys to prevent being DoSed."
            )

        # Calculate the skipped message keys and keep the receiving chain length updated
        for _ in range(num_skipped_keys):
            skipped_message_keys[(self.__other_ratchet_pub, receiving_chain_length)] = \
                await self.__symmetric_key_ratchet.next_decryption_key()
            receiving_chain_length += 1

        # Check whether a message key is requested that was derived before
        if header.sending_chain_length < receiving_chain_length:
            raise DuplicateMessageException(
                f"It seems like this message was already decrypted before. Header: {header}"
            )

        # Finally, derive the requested message key and return it with the skipped message keys
        next_decryption_key = await self.__symmetric_key_ratchet.next_decryption_key()

        return next_decryption_key, skipped_message_keys
