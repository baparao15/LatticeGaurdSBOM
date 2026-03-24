"""
Route: /latticeguard-api/audit
Phase 4 — PQC Signature Timeline / Audit Log
"""
from fastapi import APIRouter
from store.audit_store import audit_store

router = APIRouter()


@router.get("/events")
def get_events():
    """Return all cryptographic audit events for this session."""
    events = audit_store.get_events()
    return {
        "events": events,
        "total": len(events),
        "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
        "fips_standard": "FIPS-204",
        "security_level": "NIST-Level-3",
    }


@router.delete("/events")
def clear_events():
    """Clear the audit log (for starting a fresh session)."""
    audit_store.clear()
    return {"cleared": True}
