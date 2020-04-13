import os
import random
from typing import Set

from doubleratchet.recommended import HashFunction, kdf_hkdf, kdf_separate_hmacs

def generate_unique_random_data(lower_bound: int, upper_bound: int, data_set: Set[bytes]) -> bytes:
    while True:
        data = os.urandom(random.randrange(lower_bound, upper_bound))
        if data not in data_set:
            data_set.add(data)
            return data

def test_kdf_hkdf() -> None:
    for hash_function in HashFunction:
        key_set:         Set[bytes] = set()
        input_data_set:  Set[bytes] = set()
        output_data_set: Set[bytes] = set()
        info_set:        Set[bytes] = set()

        for _ in range(50):
            # Generate (unique) random parameters
            key        = generate_unique_random_data(0, 2 ** 16, key_set)
            input_data = generate_unique_random_data(0, 2 ** 16, input_data_set)
            info       = generate_unique_random_data(0, 2 ** 16, info_set)

            output_data_length = random.randrange(2, 255 * hash_function.as_cryptography.digest_size + 1)

            # Prepare the KDF
            class KDF(kdf_hkdf.KDF):
                @staticmethod
                def _get_hash_function() -> HashFunction:
                    return hash_function # pylint: disable=cell-var-from-loop

                @staticmethod
                def _get_info() -> bytes:
                    return info # pylint: disable=cell-var-from-loop

            # Perform a key derivation
            output_data = KDF.derive(key, input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert determinism
            for _ in range(25):
                output_data_repeated = KDF.derive(key, input_data, output_data_length)
                assert output_data_repeated == output_data

def test_kdf_separate_hmacs() -> None:
    for hash_function in HashFunction:
        key_set:         Set[bytes] = set()
        input_data_set:  Set[bytes] = set()
        output_data_set: Set[bytes] = set()

        # Prepare the KDF
        class KDF(kdf_separate_hmacs.KDF):
            @staticmethod
            def _get_hash_function() -> HashFunction:
                return hash_function # pylint: disable=cell-var-from-loop

        for _ in range(50):
            # Generate (unique) random parameters
            key        = generate_unique_random_data(0, 2 ** 16, key_set)
            input_data = generate_unique_random_data(1, 2 ** 8, input_data_set)

            output_data_length = len(input_data) * hash_function.as_cryptography.digest_size

            # Perform a key derivation
            output_data = KDF.derive(key, input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert determinism
            for _ in range(25):
                output_data_repeated = KDF.derive(key, input_data, output_data_length)
                assert output_data_repeated == output_data
