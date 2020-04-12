import random
from typing import Set

import doubleratchet
from doubleratchet.recommended import kdf_hkdf
from doubleratchet.recommended.hash_function import HashFunction

from test_recommended_kdfs import generate_unique_random_data

class KDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "test_kdf_chain info".encode("ASCII")

def test_kdf_chain() -> None:
    initial_key_set: Set[bytes] = set()
    input_data_set:  Set[bytes] = set()
    output_data_set: Set[bytes] = set()

    for _ in range(25):
        # Generate random parameters
        while True:
            initial_key = generate_unique_random_data(0, 2 ** 16, initial_key_set)
            input_data  = generate_unique_random_data(0, 2 ** 16, input_data_set)

            output_data_length = random.randrange(2, 2 ** 16)

            digest_size = HashFunction.SHA_512.as_cryptography.digest_size
            if len(initial_key) + output_data_length <= 255 * digest_size:
                break

        # Create the KDF chain
        kdf_chain = doubleratchet.kdf_chain.KDFChain.create(KDF, initial_key)

        # Perform 100 derivation steps
        for step_counter in range(100):
            output_data = kdf_chain.step(input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert that the chain length is counted correctly
            assert kdf_chain.length == step_counter + 1

        # Save the output data derived in the final step to be able to confirm determinism
        final_step_output_data = output_data

        # Create another KDF chain with the same parameters
        output_data_set.clear()
        kdf_chain = doubleratchet.kdf_chain.KDFChain.create(KDF, initial_key)

        # Repeat the 100 derivation steps
        for step_counter in range(100):
            output_data = kdf_chain.step(input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert that the chain length is counted correctly
            assert kdf_chain.length == step_counter + 1

        # Assert determinism
        assert output_data == final_step_output_data

        # Create another KDF chain with the same parameters
        output_data_set.clear()
        kdf_chain = doubleratchet.kdf_chain.KDFChain.create(KDF, initial_key)

        # Repeat only the first 50 derivation steps
        for step_counter in range(50):
            output_data = kdf_chain.step(input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert that the chain length is counted correctly
            assert kdf_chain.length == step_counter + 1

        # Serialize and deserialize the KDF chain
        kdf_chain = doubleratchet.kdf_chain.KDFChain.deserialize(kdf_chain.serialize(), KDF)

        # Perform the remaining 50 derivation steps
        for step_counter in range(50):
            output_data = kdf_chain.step(input_data, output_data_length)

            # Assert correct length and uniqueness of the result
            assert len(output_data) == output_data_length
            assert output_data not in output_data_set
            output_data_set.add(output_data)

            # Assert that the chain length is counted correctly
            assert kdf_chain.length == step_counter + 51

        # Assert that the serialization didn't modify the chain
        assert output_data == final_step_output_data