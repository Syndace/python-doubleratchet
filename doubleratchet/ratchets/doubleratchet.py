from .dhratchet import DHRatchet
from ..exceptions import TooManySavedMessageKeysException
from ..header import Header

class DoubleRatchet(DHRatchet):
    def __init__(self, config):
        self.__config = config.dr_config

        # This super constructor may already trigger _onNewChainKey,
        # that's why the config has to be saved before the constructor gets called.
        super(DoubleRatchet, self).__init__(config)

        self.__saved_message_keys = {}

    def _onNewChainKey(self, key, chain):
        """
        Update the symmetric key ratchet with the new key.
        """

        self.__config.skr.step(key, chain)

    def decryptMessage(self, ciphertext, header, ad = None):
        if ad == None:
            ad = self.__config.ad

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
            self.__config.skr.nextDecryptionKey(),
            header,
            ad
        )

    def __decrypt(self, ciphertext, key, header, ad):
        return self.__config.aead.decrypt(ciphertext, key, self._makeAD(header, ad))

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
        if self.__config.skr.receiving_chain_length == None:
            return

        num_keys_to_save = target - self.__config.skr.receiving_chain_length

        # Check whether the mk_store_max value would get crossed saving these message keys
        if num_keys_to_save + len(self.__saved_message_keys) > self.__config.mk_store_max:
            raise TooManySavedMessageKeysException()

        # Save all message keys until the target chain length was reached
        while self.__config.skr.receiving_chain_length < target:
            next_key  = self.__config.skr.nextDecryptionKey()
            key_index = self.__config.skr.receiving_chain_length - 1

            self.__saved_message_keys[(self.other_enc, key_index)] = next_key

    def encryptMessage(self, message, ad = None):
        if ad == None:
            ad = self.__config.ad

        # Prepare the header for this message
        header = Header(
            self.enc,
            self.__config.skr.sending_chain_length,
            self.__config.skr.previous_sending_chain_length
        )

        # Encrypt the message
        ciphertext = self.__config.aead.encrypt(
            message,
            self.__config.skr.nextEncryptionKey(),
            self._makeAD(header, ad)
        )

        return {
            "header"     : header,
            "ciphertext" : ciphertext
        }

    def _makeAD(self, header, ad):
        raise NotImplementedError
