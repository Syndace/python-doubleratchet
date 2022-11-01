from typing import Type

from .crypto_provider import CryptoProvider


CryptoProviderImpl: Type[CryptoProvider]
try:
    from .crypto_provider_brython import CryptoProviderImpl
except ImportError:
    from .crypto_provider_cryptography import CryptoProviderImpl


__all__ = [
    "CryptoProviderImpl"
]
