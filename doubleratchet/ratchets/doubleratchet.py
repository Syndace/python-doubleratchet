from __future__ import absolute_import

from .dhratchet import DHRatchet
from ..header import Header

class DoubleRatchet(DHRatchet):
    def __init__(self, config):
        self.__config = config.dr_config

        # This super constructor may already trigger _onNewChainKey, that's why the config has to be saved before the constructor gets called
        super(DoubleRatchet, self).__init__(config)

        self.__saved_message_keys = {}

    def _onNewChainKey(self, key, chain):
        """
        Update the symmetric key ratchet with the new key.
        """

        self.__config.skr.step(key, chain)

    def decodeMessage(self, ciphertext, header, ad = None):
        if ad == None:
            ad = self.__config.ad

        # Try to decode the message using a previously saved message key
        plaintext = self.__decodeSavedMessage(ciphertext, header, ad)
        if plaintext:
            return plaintext

        # Check, whether the public key will trigger a dh ratchet step
        if self.triggersStep(header.dh_pub):
            # Save missed message keys for the current receiving chain
            self.__saveMessageKeys(header.pn)

            # Perform the step
            self.step(header.dh_pub)

        # Save missed message keys for the current receiving chain
        self.__saveMessageKeys(header.n)

        # Finally decode the message and return the plaintext
        return self.__decode(ciphertext, self.__config.skr.nextDecryptionKey(), header, ad)

    def __decode(self, ciphertext, key, header, ad):
        return self.__config.aead.decrypt(ciphertext, key, self._makeAD(header, ad))

    def __decodeSavedMessage(self, ciphertext, header, ad):
        try:
            # Search for a saved key for this message
            key = self.__saved_message_keys[(header.dh_pub, header.n)]
        except KeyError:
            # If there was no message key saved for this message, return None
            return None

        # Delete the entry
        del self.__saved_message_keys[(header.dh_pub, header.n)]

        # Finally decode the message and return the plaintext
        return self.__decode(ciphertext, key, header, ad)

    def __saveMessageKeys(self, target):
        if self.__config.skr.receiving_chain_length == None:
            return

        # Check, whether the mk_store_max value would get crossed by saving these message keys
        if (target - self.__config.skr.receiving_chain_length) + len(self.__saved_message_keys) > self.__config.mk_store_max:
            raise TooManySavedMessageKeysException()

        # Save all message keys until the target chain length was reached
        while self.__config.skr.receiving_chain_length < target:
            next_key = self.__config.skr.nextDecryptionKey()
            self.__saved_message_keys[(self.other_pub, self.__config.skr.receiving_chain_length - 1)] = next_key

    def encodeMessage(self, plaintext, ad = None):
        if ad == None:
            ad = self.__config.ad

        # Prepare the header for this message
        header = Header(self.pub, self.__config.skr.sending_chain_length, self.__config.skr.previous_sending_chain_length)

        # Encrypt the message
        ciphertext = self.__config.aead.encrypt(plaintext, self.__config.skr.nextEncryptionKey(), self._makeAD(header, ad))

        return {
            "header": header,
            "ciphertext": ciphertext
        }

    def _makeAD(self, header, ad):
        raise NotImplementedError
