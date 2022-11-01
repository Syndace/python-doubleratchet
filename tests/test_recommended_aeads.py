import enum
import random
from typing import Optional, Set, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from doubleratchet import AuthenticationFailedException, DecryptionFailedException
from doubleratchet.recommended import aead_aes_hmac, HashFunction
from doubleratchet.recommended.crypto_provider_cryptography import CryptoProviderImpl

from .test_recommended_kdfs import generate_unique_random_data


__all__ = [  # pylint: disable=unused-variable
    "test_aead_aes_hmac"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio  # pylint: disable=unused-variable


def flip_random_bit(data: bytes) -> bytes:
    """
    In an array of bytes, flip a single random bit.

    Args:
        data: The data to manipulate.

    Return:
        The data with a single bit flipped somewhere.
    """

    if len(data) == 0:
        return data

    modify_byte = random.randrange(len(data))
    modify_bit = random.randrange(8)

    data_mut = bytearray(data)
    data_mut[modify_byte] ^= 1 << modify_bit
    return bytes(data_mut)


@enum.unique
class EvilEncryptModification(enum.Enum):
    """
    Enumartion of the evil encryption modifications tested, i.e. where bit flips are inserted.
    """

    ENCRYPTION_KEY = 1
    IV = 2
    PADDING = 3
    CIPHERTEXT = 4


def make_aead(
    hash_function: HashFunction,
    info: bytes,
    modify: Optional[EvilEncryptModification]
) -> Type[aead_aes_hmac.AEAD]:
    """
    Return a subclass of :class:`~doubleratchet.recommended.aead_aes_hmac.AEAD` using given hash function and
    info, whose :meth:`~doubleratchet.AEAD.encrypt` method was modified to optionally induce a bit flip
    somewhere.

    Args:
        hash_function: The hash function to use.
        info: The info to use.
        modify: The modification to perform, if any.

    Returns:
        The subclass.
    """

    class AEAD(aead_aes_hmac.AEAD):  # pylint: disable=missing-class-docstring
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_function

        @staticmethod
        def _get_info() -> bytes:
            return info

        @classmethod
        async def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
            # A copy of aead_aes_hmac.AEAD's encrypt implementation, but with bit flips inserted at various
            # points.
            encryption_key, authentication_key, iv = await cls.__derive(
                key,
                hash_function,
                info
            )

            if modify is EvilEncryptModification.ENCRYPTION_KEY:
                # Flip a random bit of the encryption key
                encryption_key = flip_random_bit(encryption_key)

            if modify is EvilEncryptModification.IV:
                # Flip a random bit of the IV
                iv = flip_random_bit(iv)

            padder = PKCS7(128).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()

            if modify is EvilEncryptModification.PADDING:
                # Flip the most significant bit of the very last byte
                padded_plaintext_mut = bytearray(padded_plaintext)
                padded_plaintext_mut[-1] ^= 1 << 7
                padded_plaintext = bytes(padded_plaintext_mut)

            aes = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            ).encryptor()
            ciphertext = aes.update(padded_plaintext) + aes.finalize()  # pylint: disable=no-member

            if modify is EvilEncryptModification.CIPHERTEXT:
                # Remove the last byte of the ciphertext
                ciphertext = ciphertext[:-1]

            # Calculate the authentication tag
            auth = await CryptoProviderImpl.hmac_calculate(
                authentication_key,
                hash_function,
                associated_data + ciphertext
            )

            # Append the authentication tag to the ciphertext
            return ciphertext + auth

    return AEAD


async def test_aead_aes_hmac() -> None:
    """
    Test the AES/HMAC-based AEAD recommended implementation.
    """

    for hash_function in HashFunction:
        key_set: Set[bytes] = set()
        data_set: Set[bytes] = set()
        ad_set: Set[bytes] = set()
        info_set: Set[bytes] = set()

        for _ in range(100):
            # Generate (unique) random parameters
            key = generate_unique_random_data(0, 2 ** 16, key_set)
            data = generate_unique_random_data(1, 2 ** 6, data_set)
            associated_data = generate_unique_random_data(0, 2 ** 16, ad_set)
            info = generate_unique_random_data(0, 2 ** 16, info_set)

            # Prepare the AEAD
            UnmodifiedAEAD = make_aead(hash_function, info, None)

            # Test en-/decryption
            ciphertext = await UnmodifiedAEAD.encrypt(data, key, associated_data)
            plaintext = await UnmodifiedAEAD.decrypt(ciphertext, key, associated_data)
            assert data == plaintext

            for _ in range(50):
                # Flip a random bit in the ciphertext and test the reaction during decryption:
                try:
                    await UnmodifiedAEAD.decrypt(flip_random_bit(ciphertext), key, associated_data)
                    assert False
                except AuthenticationFailedException:
                    pass

                # Flip a random bit in the key and test the reaction during decryption:
                try:
                    await UnmodifiedAEAD.decrypt(ciphertext, flip_random_bit(key), associated_data)
                    assert False
                except AuthenticationFailedException:
                    pass

                # Flip a random bit in the associated data and test the reaction during decryption:
                try:
                    await UnmodifiedAEAD.decrypt(ciphertext, key, flip_random_bit(associated_data))
                    assert False
                except AuthenticationFailedException:
                    pass

            # A DecryptionFailedException can only be triggered by manually crafting a faulty ciphertext but
            # adding correct authentication on top of it. That means modifications to the key and to the
            # associated data will always be caught by an AuthenticationFailedException, only modified
            # ciphertexts with correct auth tag can trigger a DecryptionFailedException.

            EvilEncryptionKeyAEAD = make_aead(hash_function, info, EvilEncryptModification.ENCRYPTION_KEY)
            EvilIVAEAD = make_aead(hash_function, info, EvilEncryptModification.IV)
            EvilPaddingAEAD = make_aead(hash_function, info, EvilEncryptModification.PADDING)
            EvilCiphertextAEAD = make_aead(hash_function, info, EvilEncryptModification.CIPHERTEXT)

            ciphertext = await EvilEncryptionKeyAEAD.encrypt(data, key, associated_data)
            # Due to the modified key, a different plaintext than the original should be decrypted. This
            # causes either an error in the unpadding or succeeds but produces wrong plaintext:
            try:
                plaintext = await UnmodifiedAEAD.decrypt(ciphertext, key, associated_data)
                # Either the produced plaintext is wrong...
                assert plaintext != data
            except DecryptionFailedException as e:
                # ...or the unpadding fails.
                assert "padded incorrectly" in str(e)

            ciphertext = await EvilIVAEAD.encrypt(data, key, associated_data)
            # The modified IV only influences the first block of the plaintext, thus a modified IV
            # might neither cause a decryption error nor an unpadding error. Instead, it will likely
            # succeed but produce a slightly wrong plaintext:
            try:
                plaintext = await UnmodifiedAEAD.decrypt(ciphertext, key, associated_data)
                # Either the produced plaintext is wrong...
                assert plaintext != data
            except DecryptionFailedException as e:
                # ...or the unpadding fails.
                assert "padded incorrectly" in str(e)

            ciphertext = await EvilPaddingAEAD.encrypt(data, key, associated_data)
            try:
                await UnmodifiedAEAD.decrypt(ciphertext, key, associated_data)
                assert False
            except DecryptionFailedException as e:
                assert "padded incorrectly" in str(e)

            ciphertext = await EvilCiphertextAEAD.encrypt(data, key, associated_data)
            try:
                await UnmodifiedAEAD.decrypt(ciphertext, key, associated_data)
                assert False
            except DecryptionFailedException as e:
                assert "decryption failed" in str(e).lower()
