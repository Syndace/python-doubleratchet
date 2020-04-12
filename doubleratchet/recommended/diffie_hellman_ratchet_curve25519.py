from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .. import diffie_hellman_ratchet
from ..types import KeyPair

class DiffieHellmanRatchet(diffie_hellman_ratchet.DiffieHellmanRatchet):
    """
    An implementation of :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet` using Curve25519
    keys and performing X25519 key exchanges.
    """

    @staticmethod
    def _generate_key_pair() -> KeyPair:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return KeyPair(priv=priv, pub=pub)

    @staticmethod
    def _perform_diffie_hellman(own_key_pair: KeyPair, other_public_key: bytes) -> bytes:
        private_key = X25519PrivateKey.from_private_bytes(own_key_pair.priv)
        public_key = X25519PublicKey.from_public_bytes(other_public_key)

        return private_key.exchange(public_key)
