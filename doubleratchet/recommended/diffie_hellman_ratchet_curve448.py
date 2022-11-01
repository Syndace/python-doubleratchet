from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from .. import diffie_hellman_ratchet


__all__ = [  # pylint: disable=unused-variable
    "DiffieHellmanRatchet"
]


class DiffieHellmanRatchet(diffie_hellman_ratchet.DiffieHellmanRatchet):
    """
    An implementation of :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet` using Curve448
    keys and performing X448 key exchanges.

    Implementation relies on the Python package `cryptography <https://github.com/pyca/cryptography>`_.
    """

    @staticmethod
    def _generate_priv() -> bytes:
        return X448PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def _derive_pub(priv: bytes) -> bytes:
        return X448PrivateKey.from_private_bytes(priv).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _perform_diffie_hellman(own_priv: bytes, other_pub: bytes) -> bytes:
        return X448PrivateKey.from_private_bytes(own_priv).exchange(X448PublicKey.from_public_bytes(
            other_pub
        ))
