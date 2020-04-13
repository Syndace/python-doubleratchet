# pylint: disable=too-many-statements

import enum
import random
from typing import Set, Callable, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from doubleratchet import AuthenticationFailedException, DecryptionFailedException
from doubleratchet.recommended import aead_aes_hmac, HashFunction

from test_recommended_kdfs import generate_unique_random_data

def flip_random_bit(data: bytes) -> bytes:
    if len(data) == 0:
        return data

    modify_byte = random.randrange(len(data))
    modify_bit  = random.randrange(8)

    data_mut = bytearray(data)
    data_mut[modify_byte] ^= 1 << modify_bit
    return bytes(data_mut)

@enum.unique
class EvilEncryptModification(enum.Enum):
    EncryptionKey = 1
    IV = 2
    Padding = 3
    Ciphertext = 4

def encrypt(
    hash_function: hashes.HashAlgorithm,
    key: bytes,
    info: bytes,
    plaintext: bytes,
    associated_data: bytes,
    derive: Callable[[bytes, hashes.HashAlgorithm, bytes], Tuple[bytes, bytes, bytes]],
    modify: EvilEncryptModification
) -> bytes:
    encryption_key, authentication_key, iv = derive(key, hash_function, info)

    if modify is EvilEncryptModification.EncryptionKey:
        # Flip a random bit of the encryption key
        encryption_key = flip_random_bit(encryption_key)

    if modify is EvilEncryptModification.IV:
        # Flip a random bit of the IV
        iv = flip_random_bit(iv)

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    if modify is EvilEncryptModification.Padding:
        # Flip the most significant bit of the very last byte
        padded_plaintext_mut = bytearray(padded_plaintext)
        padded_plaintext_mut[-1] ^= 1 << 7
        padded_plaintext = bytes(padded_plaintext_mut)

    aes = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = aes.update(padded_plaintext) + aes.finalize()

    if modify is EvilEncryptModification.Ciphertext:
        # Remove the last byte of the ciphertext
        ciphertext = ciphertext[:-1]

    auth = hmac.HMAC(authentication_key, hash_function, backend=default_backend())
    auth.update(associated_data)
    auth.update(ciphertext)
    return ciphertext + auth.finalize()

def test_aead_aes_hmac() -> None:
    for hash_function in HashFunction:
        key_set:  Set[bytes] = set()
        data_set: Set[bytes] = set()
        ad_set:   Set[bytes] = set()
        info_set: Set[bytes] = set()

        for _ in range(100):
            # Generate (unique) random parameters
            key  = generate_unique_random_data(0, 2 ** 16, key_set)
            data = generate_unique_random_data(1, 2 ** 6, data_set)
            ad   = generate_unique_random_data(0, 2 ** 16, ad_set)
            info = generate_unique_random_data(0, 2 ** 16, info_set)

            # Prepare the AEAD
            class AEAD(aead_aes_hmac.AEAD):
                @staticmethod
                def _get_hash_function() -> HashFunction:
                    return hash_function # pylint: disable=cell-var-from-loop

                @staticmethod
                def _get_info() -> bytes:
                    return info # pylint: disable=cell-var-from-loop

            # Test en-/decryption
            ciphertext = AEAD.encrypt(data, key, ad)
            plaintext  = AEAD.decrypt(ciphertext, key, ad)
            assert data == plaintext

            for _ in range(50):
                # Flip a random bit in the ciphertext and test the reaction during decryption:
                try:
                    AEAD.decrypt(flip_random_bit(ciphertext), key, ad)
                    assert False
                except AuthenticationFailedException:
                    pass

                # Flip a random bit in the key and test the reaction during decryption:
                try:
                    AEAD.decrypt(ciphertext, flip_random_bit(key), ad)
                    assert False
                except AuthenticationFailedException:
                    pass

                # Flip a random bit in the associated data and test the reaction during decryption:
                try:
                    AEAD.decrypt(ciphertext, key, flip_random_bit(ad))
                    assert False
                except AuthenticationFailedException:
                    pass

            # A DecryptionFailedException can only be triggered by manually crafting a faulty ciphertext but
            # adding correct authentication on top of it. That means modifications to the key and to the
            # associated data will always be caught by an AuthenticationFailedException, only modified
            # ciphertexts with correct auth tag can trigger a DecryptionFailedException.

            class EvilEncryptionKeyAEAD(AEAD):
                @classmethod
                def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
                    return encrypt(
                        cls._get_hash_function().as_cryptography,
                        key,
                        cls._get_info(),
                        plaintext,
                        associated_data,
                        cls._AEAD__derive, # type: ignore # pylint: disable=no-member
                        EvilEncryptModification.EncryptionKey
                    )

            class EvilIVAEAD(AEAD):
                @classmethod
                def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
                    return encrypt(
                        cls._get_hash_function().as_cryptography,
                        key,
                        cls._get_info(),
                        plaintext,
                        associated_data,
                        cls._AEAD__derive, # type: ignore # pylint: disable=no-member
                        EvilEncryptModification.IV
                    )

            class EvilPaddingAEAD(AEAD):
                @classmethod
                def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
                    return encrypt(
                        cls._get_hash_function().as_cryptography,
                        key,
                        cls._get_info(),
                        plaintext,
                        associated_data,
                        cls._AEAD__derive, # type: ignore # pylint: disable=no-member
                        EvilEncryptModification.Padding
                    )

            class EvilCiphertextAEAD(AEAD):
                @classmethod
                def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
                    return encrypt(
                        cls._get_hash_function().as_cryptography,
                        key,
                        cls._get_info(),
                        plaintext,
                        associated_data,
                        cls._AEAD__derive, # type: ignore # pylint: disable=no-member
                        EvilEncryptModification.Ciphertext
                    )

            ciphertext = EvilEncryptionKeyAEAD.encrypt(data, key, ad)
            # Due to the modified key, a different plaintext than the original should be decrypted. This
            # causes either an error in the unpadding or succeeds but produces wrong plaintext:
            try:
                plaintext = AEAD.decrypt(ciphertext, key, ad)
                # Either the produced plaintext is wrong...
                assert plaintext != data
            except DecryptionFailedException as e:
                # ...or the unpadding fails.
                assert "padded incorrectly" in str(e)

            ciphertext = EvilIVAEAD.encrypt(data, key, ad)
            # The modified IV only influences the first block of the plaintext, thus a modified IV
            # might neither cause a decryption error nor an unpadding error. Instead, it will likely
            # succeed but produce a slightly wrong plaintext:
            try:
                plaintext = AEAD.decrypt(ciphertext, key, ad)
                # Either the produced plaintext is wrong...
                assert plaintext != data
            except DecryptionFailedException as e:
                # ...or the unpadding fails.
                assert "padded incorrectly" in str(e)

            ciphertext = EvilPaddingAEAD.encrypt(data, key, ad)
            try:
                AEAD.decrypt(ciphertext, key, ad)
                assert False
            except DecryptionFailedException as e:
                assert "padded incorrectly" in str(e)

            ciphertext = EvilCiphertextAEAD.encrypt(data, key, ad)
            try:
                AEAD.decrypt(ciphertext, key, ad)
                assert False
            except DecryptionFailedException as e:
                assert "decryption failed" in str(e).lower()
