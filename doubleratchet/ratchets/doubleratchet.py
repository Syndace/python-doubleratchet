from __future__ import absolute_import

from .dhratchet import DHRatchet
from ..exceptions import TooManySavedMessageKeysException
from ..header import Header

import base64
import json

class DoubleRatchet(DHRatchet):
    """
    An implementation of the Ratchet interface, which builds the core of the DoubleRatchet
    protocol by linking all parts into one class.

    A double ratchet allows message encryption providing perfect forward secrecy. A double
    ratchet instance synchronizes with a second instance using Diffie-Hellman
    calculations, that are provided by the DHRatchet class.

    For details on how the protocol works, take a look at the specification by
    WhisperSystems:
    https://signal.org/docs/specifications/doubleratchet/
    """

    def __init__(
        self,
        symmetric_key_ratchet,
        aead,
        ad,
        message_key_store_max,
        *args,
        **kwargs
    ):
        """
        Initialize a new DoubleRatchet.

        :param symmetric_key_ratchet: An instance of the SymmetricKeyRatchet class, which
            is used to derive en- and decryption keys for message exchange.
        :param aead: An instance of an implementation of the AEAD interface, which is used
            to provice authenticated message encryption and is fed with the message keys
            derived using the symmetric key ratchet.
        :param ad: Some associated data to use for message authentication, encoded as a
            bytes-like object.
        :param message_key_store_max: An integer defining the maximum amount of message
            keys to store before raising an exception. This mechanism allows out-of-order
            messages, by storing message keys of out-of-order messages instead of
            discarding them.
        """

        self.__skr     = symmetric_key_ratchet
        self.__aead    = aead
        self.__ad      = ad
        self.__mks_max = message_key_store_max

        self.__saved_message_keys = {}

        # The super constructor may already call the _onNewChainKey method,
        # that's why the skr must be stored into self, before the call can be made.
        super(DoubleRatchet, self).__init__(*args, **kwargs)

    def serialize(self):
        smks = {}

        for key, value in self.__saved_message_keys.items():
            key = json.dumps({
                "pub"   : base64.b64encode(key[0]).decode("US-ASCII"),
                "index" : key[1]
            })

            smks[key] = base64.b64encode(value).decode("US-ASCII")

        return {
            "super" : super(DoubleRatchet, self).serialize(),
            "smks"  : smks
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(DoubleRatchet, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        smks = {}

        for key, value in serialized["smks"].items():
            key = json.loads(key)

            pub   = base64.b64decode(key["pub"].encode("US-ASCII"))
            index = key["index"]

            smks[(pub, index)] = base64.b64decode(value.encode("US-ASCII"))

        self.__saved_message_keys = smks

        return self

    def _onNewChainKey(self, key, chain):
        """
        Update the symmetric key ratchet with the new key.
        """

        self.__skr.step(key, chain)

    def decryptMessage(self, ciphertext, header, ad = None, _DEBUG_newRatchetKey = None):
        """
        Decrypt a message using this double ratchet session.

        :param ciphertext: A bytes-like object encoding the message to decrypt.
        :param header: An instance of the Header class. This should have been sent
            together with the ciphertext.
        :param ad: A bytes-like object encoding the associated data to use for message
            authentication. Pass None to use the associated data set during construction.
        :returns: The plaintext.

        :raises AuthenticationFailedException: If checking the authentication for this
            message failed.
        :raises NotInitializedException: If this double ratchet session is not yet
            initialized with a key pair, thus not prepared to decrypt an incoming message.
        :raises TooManySavedMessageKeysException: If more than message_key_store_max have
            to be stored to decrypt this message.
        """

        if ad == None:
            ad = self.__ad

        # Try to decrypt the message using a previously saved message key
        plaintext = self.__decryptSavedMessage(ciphertext, header, ad)
        if plaintext:
            return plaintext

        # Check, whether the public key will trigger a dh ratchet step
        if self.triggersStep(header.dh_pub):
            # Save missed message keys for the current receiving chain
            self.__saveMessageKeys(header.pn)

            # Perform the step
            self.step(header.dh_pub, _DEBUG_newRatchetKey = _DEBUG_newRatchetKey)

        # Save missed message keys for the current receiving chain
        self.__saveMessageKeys(header.n)

        # Finally decrypt the message and return the plaintext
        return self.__decrypt(
            ciphertext,
            self.__skr.nextDecryptionKey(),
            header,
            ad
        )

    def __decrypt(self, ciphertext, key, header, ad):
        return self.__aead.decrypt(ciphertext, key, self._makeAD(header, ad))

    def __decryptSavedMessage(self, ciphertext, header, ad):
        try:
            # Search for a saved key for this message
            key = self.__saved_message_keys[(header.dh_pub, header.n)]
        except KeyError:
            # If there was no message key saved for this message, return None
            return None

        # Delete the entry
        del self.__saved_message_keys[(header.dh_pub, header.n)]

        # Finally decrypt the message and return the plaintext
        return self.__decrypt(ciphertext, key, header, ad)

    def __saveMessageKeys(self, target):
        if self.__skr.receiving_chain_length == None:
            return

        num_keys_to_save = target - self.__skr.receiving_chain_length

        # Check whether the mk_store_max value would get crossed saving these message keys
        if num_keys_to_save + len(self.__saved_message_keys) > self.__mks_max:
            raise TooManySavedMessageKeysException()

        # Save all message keys until the target chain length was reached
        while self.__skr.receiving_chain_length < target:
            next_key  = self.__skr.nextDecryptionKey()
            key_index = self.__skr.receiving_chain_length - 1

            self.__saved_message_keys[(self.other_pub, key_index)] = next_key

    def encryptMessage(self, message, ad = None):
        """
        Encrypt a message using this double ratchet session.

        :param message: A bytes-like object encoding the message to encrypt.
        :param ad: A bytes-like object encoding the associated data to use for message
            authentication. Pass None to use the associated data set during construction.
        :returns: A dictionary containing the message header and ciphertext. The header is
            required to synchronize the double ratchet of the receiving party. Send it
            along with the ciphertext.

        The returned dictionary consists of two keys: "header", which includes an instance
        of the Header class and "ciphertext", which includes the encrypted message encoded
        as a bytes-like object.

        :raises NotInitializedException: If this double ratchet session is not yet
            initialized with the other parties public key, thus not ready to encrypt a
            message to that party.
        """

        if ad == None:
            ad = self.__ad

        # Prepare the header for this message
        header = Header(
            self.pub,
            self.__skr.sending_chain_length,
            self.__skr.previous_sending_chain_length
        )

        # Encrypt the message
        ciphertext = self.__aead.encrypt(
            message,
            self.__skr.nextEncryptionKey(),
            self._makeAD(header, ad)
        )

        return {
            "header"     : header,
            "ciphertext" : ciphertext
        }

    def _makeAD(self, header, ad):
        """
        Construct specific associated data for this message from the message header and
        the general associated data.

        :param header: An instance of the Header class.
        :param ad: A bytes-like object encoding the general associated data.
        :returns: A bytes-like object encoding the message-specific associated data.
        """

        raise NotImplementedError
