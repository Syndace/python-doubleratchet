import os
import random
from typing import Set, Type

from doubleratchet.recommended import HashFunction, kdf_hkdf, kdf_separate_hmacs


__all__ = [  # pylint: disable=unused-variable
    "test_kdf_hkdf",
    "test_kdf_separate_hmacs"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio  # pylint: disable=unused-variable


def make_kdf_hkdf(hash_function: HashFunction, info: bytes) -> Type[kdf_hkdf.KDF]:
    """
    Create a subclass of :class:`~doubleratchet.recommended.kdf_hkdf.KDF` using given hash function and info.

    Args:
        hash_function: The hash function to use.
        info: The info to use.

    Returns:
        The subclass.
    """

    class KDF(kdf_hkdf.KDF):  # pylint: disable=missing-class-docstring
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_function

        @staticmethod
        def _get_info() -> bytes:
            return info

    return KDF


def make_kdf_separate_hmacs(hash_function: HashFunction) -> Type[kdf_separate_hmacs.KDF]:
    """
    Create a subclass of :class:`~doubleratchet.recommended.kdf_separate_hmacs.KDF` using given hash function.

    Args:
        hash_function: The hash function to use.

    Returns:
        The subclass.
    """

    class KDF(kdf_separate_hmacs.KDF):  # pylint: disable=missing-class-docstring
        @staticmethod
        def _get_hash_function() -> HashFunction:
            return hash_function

    return KDF


def generate_unique_random_data(lower_bound: int, upper_bound: int, data_set: Set[bytes]) -> bytes:
    """
    Generate random data of random length (within certain bounds) and make sure that the generated data is
    new.

    Args:
        lower_bound: The minimum number of bytes.
        upper_bound: The maximum number of bytes (exclusive).
        data_set: The set of random data that has been generated before, for uniqueness checks.

    Returns:
        The newly generated, unique random data.
    """

    while True:
        data = os.urandom(random.randrange(lower_bound, upper_bound))
        if data not in data_set:
            data_set.add(data)
            return data


async def test_kdf_hkdf() -> None:
    """
    Test the HKDF-based recommended KDF implementation.
    """

    for hash_function in HashFunction:
        key_set: Set[bytes] = set()
        input_data_set: Set[bytes] = set()
        output_data_set: Set[bytes] = set()
        info_set: Set[bytes] = set()

        for _ in range(50):
            # Generate (unique) random parameters
            key = generate_unique_random_data(0, 2 ** 16, key_set)
            input_data = generate_unique_random_data(0, 2 ** 16, input_data_set)
            info = generate_unique_random_data(0, 2 ** 16, info_set)

            output_data_length = random.randrange(2, 255 * hash_function.hash_size + 1)

            # Prepare the KDF
            KDF = make_kdf_hkdf(hash_function, info)

            # Perform a key derivation
            output_data = await KDF.derive(key, input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert determinism
            for _ in range(25):
                output_data_repeated = await KDF.derive(key, input_data, output_data_length)
                assert output_data_repeated == output_data


async def test_kdf_separate_hmacs() -> None:
    """
    Test the separate HMAC-based recommended KDF implementation.
    """

    for hash_function in HashFunction:
        key_set: Set[bytes] = set()
        input_data_set: Set[bytes] = set()
        output_data_set: Set[bytes] = set()

        # Prepare the KDF
        KDF = make_kdf_separate_hmacs(hash_function)

        for _ in range(50):
            # Generate (unique) random parameters
            key = generate_unique_random_data(0, 2 ** 16, key_set)
            input_data = generate_unique_random_data(1, 2 ** 8, input_data_set)

            output_data_length = len(input_data) * hash_function.hash_size

            # Perform a key derivation
            output_data = await KDF.derive(key, input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert determinism
            for _ in range(25):
                output_data_repeated = await KDF.derive(key, input_data, output_data_length)
                assert output_data_repeated == output_data
