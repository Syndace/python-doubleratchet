from __future__ import absolute_import

from .dhratchet import DHRatchet
from ..exceptions import TooManySavedMessageKeysException
from ..header import Header

import base64
import json

class DoubleRatchet(DHRatchet):
    def __init__(
        self,
        symmetric_key_ratchet,
        aead,
        ad,
        message_key_store_max,
        *args,
        **kwargs
    ):
        self.__skr     = symmetric_key_ratchet
        self.__aead    = aead
        self.__ad      = ad
        self.__mks_max = message_key_store_max

        # The super constructor may already call the _onNewChainKey method,
        # that's why the skr must be stored into self, before the call can be made.
        super(DoubleRatchet, self).__init__(*args, **kwargs)

        self.__saved_message_keys = {}

    def serialize(self):
        smks = {}

        for key, value in self.__saved_message_keys.items():
            key = json.dumps({
                "enc"   : key[0].serialize(),
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

            enc = self._EncryptionKeyPair.fromSerialized(key["enc"])
            index = key["index"]

            smks[(enc, index)] = base64.b64decode(value.encode("US-ASCII"))

        self.__saved_message_keys = smks

        return self

    def _onNewChainKey(self, key, chain):
        """
        Update the symmetric key ratchet with the new key.
        """

        self.__skr.step(key, chain)

    def decryptMessage(self, ciphertext, header, ad = None):
        if ad == None:
            ad = self.__ad

        # Try to decrypt the message using a previously saved message key
        plaintext = self.__decryptSavedMessage(ciphertext, header, ad)
        if plaintext:
            return plaintext

        # Check, whether the public key will trigger a dh ratchet step
        if self.triggersStep(header.dh_enc):
            # Save missed message keys for the current receiving chain
            self.__saveMessageKeys(header.pn)

            # Perform the step
            self.step(header.dh_enc)

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
            key = self.__saved_message_keys[(header.dh_enc, header.n)]
        except KeyError:
            # If there was no message key saved for this message, return None
            return None

        # Delete the entry
        del self.__saved_message_keys[(header.dh_enc, header.n)]

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

            self.__saved_message_keys[(self.other_enc, key_index)] = next_key

    def encryptMessage(self, message, ad = None):
        if ad == None:
            ad = self.__ad

        # Prepare the header for this message
        header = Header(
            self.enc,
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
        raise NotImplementedError
