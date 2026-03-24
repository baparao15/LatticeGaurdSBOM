"""
In-memory audit log — records every cryptographic event in the current session.
Each event is signed with the system ML-DSA-65 + Ed25519 keypair.
"""
import time
import uuid
import json
import hashlib
from typing import Any, Dict, List


class AuditEvent:
    def __init__(self, event_type: str, description: str, details: Dict[str, Any]):
        self.id = str(uuid.uuid4())
        self.event_type = event_type
        self.description = description
        self.details = details
        self.timestamp = time.time()

        # Sign the event with system keys
        from store.system_keystore import system_keystore
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        event_data = {
            "id": self.id,
            "event_type": event_type,
            "description": description,
            "timestamp": self.timestamp,
        }
        canonical = json.dumps(event_data, sort_keys=True).encode()
        digest = hashlib.sha256(canonical).digest()

        ml_sig = system_keystore.ml_dsa_signer.sign(digest)
        ed_sig = system_keystore.ed25519_private_key.sign(digest)
        ed_pub = system_keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        self.ml_dsa_signature = ml_sig.hex()
        self.ed25519_signature = ed_sig.hex()
        self.public_key_ml_dsa = system_keystore.ml_dsa_public_key.hex()
        self.public_key_ed25519 = ed_pub.hex()
        self.signature_size_bytes = len(ml_sig) + len(ed_sig)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "description": self.description,
            "details": self.details,
            "timestamp": self.timestamp,
            "ml_dsa_signature": self.ml_dsa_signature,
            "ed25519_signature": self.ed25519_signature,
            "public_key_ml_dsa": self.public_key_ml_dsa,
            "public_key_ed25519": self.public_key_ed25519,
            "signature_size_bytes": self.signature_size_bytes,
            "ml_dsa_sig_size": 3293,
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        }


class AuditStore:
    def __init__(self):
        self._events: List[AuditEvent] = []

    def add_event(
        self, event_type: str, description: str, details: Dict[str, Any] = None
    ) -> AuditEvent:
        event = AuditEvent(event_type, description, details or {})
        self._events.append(event)
        return event

    def get_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def clear(self) -> None:
        self._events.clear()


# Singleton
audit_store = AuditStore()
