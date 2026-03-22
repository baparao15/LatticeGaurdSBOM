import hashlib
import json
import time
import os

from store.keystore import HAS_OQS

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from store.keystore import keystore
from models.schemas import Component, SignedComponent


def sign_component(component: Component, cves: list) -> SignedComponent:
    if not keystore.has_keys():
        raise ValueError("No keypair generated. Call /latticeguard-api/sign/keygen first.")

    component_dict = component.model_dump()
    canonical = json.dumps(component_dict, sort_keys=True)

    sha256_hash = hashlib.sha256(canonical.encode()).digest()

    ed25519_sig = keystore.ed25519_private_key.sign(sha256_hash)

    ml_dsa_sig = keystore.ml_dsa_signer.sign(sha256_hash)

    ed25519_pub = keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return SignedComponent(
        component=component,
        sha256_signed=sha256_hash.hex(),
        ed25519_signature=ed25519_sig.hex(),
        ml_dsa_signature=ml_dsa_sig.hex(),
        public_key_ed25519=ed25519_pub.hex(),
        public_key_ml_dsa=keystore.ml_dsa_public_key.hex(),
        algorithm="Hybrid(Ed25519 + ML-DSA-65)",
        fips_standard="FIPS-204",
        security_level="NIST-Level-3",
        signed_at=str(time.time()),
        signature_size_bytes=len(ml_dsa_sig) + len(ed25519_sig),
        cves=cves,
    )


def verify_component(signed: SignedComponent) -> dict:
    component_dict = signed.component.model_dump()
    canonical = json.dumps(component_dict, sort_keys=True)
    recomputed_hash = hashlib.sha256(canonical.encode()).digest()

    stored_hash = bytes.fromhex(signed.sha256_signed)
    hash_match = recomputed_hash == stored_hash

    ed25519_valid = False
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(signed.public_key_ed25519)
        )
        pub_key.verify(
            bytes.fromhex(signed.ed25519_signature),
            recomputed_hash,
        )
        ed25519_valid = True
    except Exception:
        ed25519_valid = False

    ml_dsa_valid = False
    try:
        from store.keystore import _MockMLDSA
        mock = _MockMLDSA(bytes.fromhex(signed.public_key_ml_dsa))
        ml_dsa_valid = mock.verify(
            recomputed_hash,
            bytes.fromhex(signed.ml_dsa_signature),
            bytes.fromhex(signed.public_key_ml_dsa),
        )
    except Exception:
        ml_dsa_valid = False

    return {
        "component": signed.component.name,
        "version": signed.component.version,
        "hash_match": hash_match,
        "ed25519_valid": ed25519_valid,
        "ml_dsa_valid": ml_dsa_valid,
        "overall_valid": hash_match and ed25519_valid and ml_dsa_valid,
        "recomputed_hash": recomputed_hash.hex(),
        "stored_hash": stored_hash.hex(),
    }
