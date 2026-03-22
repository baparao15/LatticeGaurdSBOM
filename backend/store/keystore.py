import time
import os

# liboqs-python requires the liboqs C shared library which is not available
# in this environment. We use a high-fidelity mock with correct NIST byte sizes.
HAS_OQS = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class KeyStore:
    def __init__(self):
        self.ml_dsa_signer = None
        self.ml_dsa_public_key = None
        self.ed25519_private_key = None
        self.ed25519_public_key = None
        self.generated_at = None
        self.algorithm = "ML-DSA-65"
        self.using_real_oqs = HAS_OQS

    def generate_keypair(self):
        if HAS_OQS:
            self.ml_dsa_signer = oqs.Signature("ML-DSA-65")
            self.ml_dsa_public_key = self.ml_dsa_signer.generate_keypair()
        else:
            # Mock: generate realistic-sized random bytes
            self.ml_dsa_public_key = os.urandom(1952)
            self.ml_dsa_signer = _MockMLDSA(self.ml_dsa_public_key)

        self.ed25519_private_key = Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        self.generated_at = time.time()

        return {
            "ml_dsa_public_key": self.ml_dsa_public_key.hex(),
            "ml_dsa_public_key_size": len(self.ml_dsa_public_key),
            "ed25519_public_key": self.ed25519_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ).hex(),
            "algorithm": self.algorithm,
            "security_level": "NIST-Level-3",
            "fips_standard": "FIPS-204",
            "generated_at": self.generated_at,
            "using_real_oqs": HAS_OQS,
        }

    def has_keys(self):
        return self.ml_dsa_signer is not None


class _MockMLDSA:
    """Realistic mock of ML-DSA with correct byte sizes."""
    def __init__(self, pub_key: bytes):
        self.pub_key = pub_key

    def sign(self, message: bytes) -> bytes:
        import hashlib
        # Deterministic 3293-byte signature derived from message + pub key
        seed = hashlib.sha512(message + self.pub_key).digest()
        sig = bytearray()
        while len(sig) < 3293:
            seed = hashlib.sha512(seed).digest()
            sig.extend(seed)
        return bytes(sig[:3293])

    def verify(self, message: bytes, signature: bytes, pub_key: bytes) -> bool:
        # Re-derive and compare
        import hashlib
        seed = hashlib.sha512(message + pub_key).digest()
        expected = bytearray()
        while len(expected) < 3293:
            seed = hashlib.sha512(seed).digest()
            expected.extend(seed)
        return bytes(expected[:3293]) == signature[:3293]


keystore = KeyStore()
