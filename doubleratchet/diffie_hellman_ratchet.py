from abc import ABCMeta, abstractmethod
from base64 import b64encode
from collections import OrderedDict
from typing import TypeVar, Type, Dict, Optional, Union, Tuple
import warnings

from .kdf import KDF
from .kdf_chain import KDFChain, KDFChainSerialized
from .symmetric_key_ratchet import SymmetricKeyRatchet, SymmetricKeyRatchetSerialized, Chain
from .types import (
    # Assertion Toolkit
    assert_in,
    assert_type,
    assert_decode_base64,

    # Helpers
    default,

    # Type Aliases
    JSONType,
    KeyPairSerialized,
    SkippedMessageKeys,

    # Structures (NamedTuples)
    Header,
    KeyPair
)

class DoSProtectionException(Exception):
    pass

class DuplicateMessageException(Exception):
    pass

class InconsistentSerializationException(Exception):
    pass

D = TypeVar("D", bound="DiffieHellmanRatchet")
DiffieHellmanRatchetSerialized = Dict[str, Union[
    KeyPairSerialized,
    str,
    KDFChainSerialized,
    SymmetricKeyRatchetSerialized
]]
class DiffieHellmanRatchet(metaclass=ABCMeta):
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
        self.__ratchet_key_pair: KeyPair
        self.__other_ratchet_pub: bytes
        self.__root_chain: KDFChain
        self.__dos_protection_threshold: int
        self.__symmetric_key_ratchet: SymmetricKeyRatchet

    @classmethod
    def create(
        cls: Type[D],
        ratchet_key_pair: Optional[KeyPair],
        other_ratchet_pub: bytes,
        root_chain_kdf: Type[KDF],
        root_chain_key: bytes,
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int
    ) -> D:
        # pylint: disable=protected-access
        """
        Create and configure a Diffie-Hellman ratchet.

        Args:
            ratchet_key_pair: The ratchet key pair to use initially with this instance.
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
            A configured instance of :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`,
            capable of sending and receiving messages.
        """

        if len(root_chain_key) != 32:
            raise ValueError("The initial key for the root chain must consist of 32 bytes.")

        self = cls()

        self.__root_chain = KDFChain.create(root_chain_kdf, root_chain_key)
        self.__dos_protection_threshold = dos_protection_threshold
        self.__symmetric_key_ratchet = SymmetricKeyRatchet.create(message_chain_kdf, message_chain_constant)

        if ratchet_key_pair is None:
            self.__ratchet_key_pair  = self._generate_key_pair()
            self.__other_ratchet_pub = other_ratchet_pub
            self.__replace_chain(Chain.Sending)
        else:
            self.__ratchet_key_pair  = ratchet_key_pair
            self.__other_ratchet_pub = b"" # A little trick to make the update trigger new chains
            self.__update_diffie_hellman_ratchet(Header(ratchet_pub=other_ratchet_pub, pn=0, n=0))

        return self

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _generate_key_pair() -> KeyPair:
        """
        Returns:
            A key pair capable of performing Diffie-Hellman key exchanges with the public key of another key
            pair. This function is recommended to generate a key pair based on the Curve25519 or Curve448
            elliptic curves
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

        raise NotImplementedError(
            "Create a subclass of DiffieHellmanRatchet and implement `_generate_key_pair`."
        )

    @staticmethod
    @abstractmethod
    def _perform_diffie_hellman(own_key_pair: KeyPair, other_public_key: bytes) -> bytes:
        """
        Args:
            own_key_pair: The ratchet key pair including the private key of this instance.
            other_public_key: The public key of the ratchet key pair of the other party.

        Returns:
            A shared secret derived from the own ratchet key pair and the other parties' ratchet public key,
            by performing Diffie-Hellman. This function is recommended to return the output from the X25519 or
            X448. There is no need to check for invalid public keys
            (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms).
        """

        raise NotImplementedError(
            "Create a subclass of DiffieHellmanRatchet and implement `_perform_diffie_hellman`."
        )

    #################
    # serialization #
    #################

    def serialize(self) -> DiffieHellmanRatchetSerialized:
        """
        Returns:
            The internal state of this instance in a JSON-friendly serializable format. Restore the instance
            using :meth:`deserialize`.
        """

        return {
            "ratchet_key_pair"      : self.__ratchet_key_pair.serialize(),
            "other_ratchet_pub"     : b64encode(self.__other_ratchet_pub).decode("ASCII"),
            "root_chain"            : self.__root_chain.serialize(),
            "symmetric_key_ratchet" : self.__symmetric_key_ratchet.serialize()
        }

    @classmethod
    def deserialize(
        cls: Type[D],
        serialized: JSONType,
        root_chain_kdf: Type[KDF],
        message_chain_kdf: Type[KDF],
        message_chain_constant: bytes,
        dos_protection_threshold: int
    ) -> D:
        # pylint: disable=protected-access
        """
        Args:
            serialized: A serialized instance of this class, as produced by :meth:`serialize`.
            root_chain_kdf: The KDF to use for the root chain. The KDF must be capable of deriving 64 bytes.
            message_chain_kdf: The KDF to use for the sending and receiving chains. The KDF must be capable of
                deriving 64 bytes.
            message_chain_constant: The constant to feed into the sending and receiving KDF chains on each
                step.
            dos_protection_threshold: The maximum number of skipped message keys to calculate. If more than
                that number of message keys are skipped, the keys are not calculated to prevent being DoSed.

        Returns:
            A configured instance of :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`
            restored from the serialized data.

        Raises:
            InconsistentSerializationException: if the serialized data does not contain an initialized sending
                chain. This can only happen when migrating from pre-stable data a Diffie-Hellman ratchet that
                was serialized before sending or receiving a single message. In this case, the serialized
                Diffie-Hellman ratchet is basically uninitialized and can be discarded/replaced with a new
                instance.
            TypeAssertionException: if the serialized data is structured/typed incorrectly.
        """

        root = assert_type(dict, serialized)

        self = cls()
        self.__ratchet_key_pair         = KeyPair.deserialize(assert_in(root, "ratchet_key_pair"))
        self.__other_ratchet_pub        = assert_decode_base64(assert_type(str, root, "other_ratchet_pub"))
        self.__root_chain               = KDFChain.deserialize(assert_in(root, "root_chain"), root_chain_kdf)
        self.__dos_protection_threshold = dos_protection_threshold
        self.__symmetric_key_ratchet    = skr = SymmetricKeyRatchet.deserialize(
            assert_in(root, "symmetric_key_ratchet"),
            message_chain_kdf,
            message_chain_constant
        )

        if skr.sending_chain_length is None:
            raise InconsistentSerializationException(
                "The serialized data does not contain an initialized sending chain."
            )

        return self

    ######################
    # ratchet management #
    ######################

    def __replace_chain(self, chain: Chain) -> None:
        self.__symmetric_key_ratchet.replace_chain(chain, self.__root_chain.step(self._perform_diffie_hellman(
            self.__ratchet_key_pair,
            self.__other_ratchet_pub
        ), 32))

    def __update_diffie_hellman_ratchet(self, header: Header) -> SkippedMessageKeys:
        """
        Args:
            header: The Diffie-Hellman ratchet header,

        Returns:
            The message keys that were skipped while updating the Diffie-Hellman ratchet.

        Raises:
            DoSProtectionException: If a huge number of message keys were skipped that have to be calculated
                first before decrypting the next message.
        """

        skipped_mks: SkippedMessageKeys = OrderedDict()

        if header.ratchet_pub != self.__other_ratchet_pub:
            rchain_length = self.__symmetric_key_ratchet.receiving_chain_length
            if rchain_length is not None:
                num_skipped_keys = max(header.pn - rchain_length, 0)
                if num_skipped_keys > self.__dos_protection_threshold:
                    warnings.warn(
                        "More than {} message keys skipped. Not calculating all of these message keys to"
                        " prevent being DoSed."
                        .format(self.__dos_protection_threshold)
                    )
                else:
                    for i in range(num_skipped_keys):
                        skipped_mks[(self.__other_ratchet_pub, rchain_length + i)] = (
                            self.__symmetric_key_ratchet.next_decryption_key()
                        )

            self.__other_ratchet_pub = header.ratchet_pub
            self.__replace_chain(Chain.Receiving)
            self.__ratchet_key_pair = self._generate_key_pair()
            self.__replace_chain(Chain.Sending)

        rchain_length = self.__symmetric_key_ratchet.receiving_chain_length
        assert rchain_length is not None # sanity check

        num_skipped_keys = max(header.n - rchain_length, 0)
        if num_skipped_keys > self.__dos_protection_threshold:
            raise DoSProtectionException(
                "More than {} message keys skipped. Not calculating all of these message keys to prevent"
                " being DoSed."
                .format(self.__dos_protection_threshold)
            )

        for i in range(num_skipped_keys):
            skipped_mks[(self.__other_ratchet_pub, rchain_length + i)] = (
                self.__symmetric_key_ratchet.next_decryption_key()
            )

        return skipped_mks

    def next_encryption_key(self) -> Tuple[bytes, Header]:
        """
        Returns:
            The next (32 bytes) encryption key derived from the sending chain and the corresponding
            Diffie-Hellman ratchet header.
        """

        sending_chain_length = self.__symmetric_key_ratchet.sending_chain_length
        assert sending_chain_length is not None # sanity check

        header = Header(
            ratchet_pub = self.__ratchet_key_pair.pub,
            pn = default(self.__symmetric_key_ratchet.previous_sending_chain_length, 0),
            n  = sending_chain_length
        )

        next_encryption_key = self.__symmetric_key_ratchet.next_encryption_key()

        return next_encryption_key, header

    def next_decryption_key(self, header: Header) -> Tuple[bytes, SkippedMessageKeys]:
        """
        Args:
            header: The Diffie-Hellman ratchet header,

        Returns:
            The next (32 bytes) decryption key derived from the receiving chain and message keys that were
            skipped while deriving the new decryption key.

        Raises:
            DoSProtectionException: If a huge number of message keys were skipped that have to be calculated
                first before decrypting the next message.
            DuplicateMessageException: If this message appears to be a duplicate.
        """

        skipped_message_keys = self.__update_diffie_hellman_ratchet(header)

        rchain_length = self.__symmetric_key_ratchet.receiving_chain_length
        assert rchain_length is not None # sanity check

        if header.n < rchain_length:
            raise DuplicateMessageException(
                "It seems like this message was already decrypted before. Header: {}".format(header)
            )

        next_decryption_key = self.__symmetric_key_ratchet.next_decryption_key()

        return next_decryption_key, skipped_message_keys
