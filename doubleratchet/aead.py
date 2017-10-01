class AEAD(object):
    def encrypt(self, plaintext, key, ad):
        raise NotImplementedError

    def decrypt(self, ciphertext, key, ad):
        raise NotImplementedError
