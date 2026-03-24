"""
System-level signing keystore — initialized at module load.
Used for signing name lists, attestations, risk scores, and audit events
BEFORE the user generates their session keypair.
"""
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from store.keystore import _MockMLDSA


class SystemKeyStore:
    def __init__(self):
        # ML-DSA-65 mock with correct NIST byte sizes (1952-byte pub key)
        self.ml_dsa_public_key: bytes = os.urandom(1952)
        self.ml_dsa_signer: _MockMLDSA = _MockMLDSA(self.ml_dsa_public_key)
        # Real Ed25519
        self.ed25519_private_key = Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()

    @property
    def ed25519_public_key_hex(self) -> str:
        return self.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @property
    def ml_dsa_public_key_hex(self) -> str:
        return self.ml_dsa_public_key.hex()


# Singleton — created once at import time, always available
system_keystore = SystemKeyStore()
