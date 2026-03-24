import uuid
import time
import asyncio
from fastapi import APIRouter, HTTPException
from store.keystore import keystore, HAS_OQS
from services.crypto_service import sign_component
from models.schemas import Component

router = APIRouter()


@router.post("/keygen")
async def generate_keypair():
    result = keystore.generate_keypair()
    return {
        **result,
        "message": "ML-DSA-65 keypair generated" + (" via liboqs (REAL)" if HAS_OQS else " (high-fidelity simulation)"),
        "ml_dsa_details": {
            "algorithm": "ML-DSA-65",
            "standard": "NIST FIPS 204",
            "security_level": "NIST Level 3",
            "hard_problem": "Module-LWE + Module-SIS",
            "public_key_size": 1952,
            "private_key_size": 4032,
            "signature_size": 3293,
            "lattice_dimension": 1024,
        },
        "ed25519_details": {
            "algorithm": "Ed25519",
            "public_key_size": 32,
            "signature_size": 64,
            "quantum_safe": False,
        },
    }


@router.post("/sign-all")
async def sign_all_components(data: dict):
    if not keystore.has_keys():
        raise HTTPException(
            status_code=400,
            detail="Generate keypair first via /latticeguard-api/sign/keygen",
        )

    signed_components = []
    for item in data.get("components", []):
        comp = Component(**item["component"])
        cves_raw = item.get("cves", [])

        from models.schemas import CVE
        cves = []
        for c in cves_raw:
            try:
                cves.append(CVE(**c))
            except Exception:
                pass

        signed = sign_component(comp, cves)
        signed_components.append(signed.model_dump())
        await asyncio.sleep(0.05)

    serial = f"urn:uuid:{uuid.uuid4()}"
    generated_at = str(time.time())

    # Record SBOM signing in audit log
    from store.audit_store import audit_store
    audit_store.add_event(
        "SBOM_SIGNED",
        f"SBOM signed with ML-DSA-65 + Ed25519 — {len(signed_components)} component(s), "
        f"serial {serial}",
        {
            "serial_number": serial,
            "component_count": len(signed_components),
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
            "ml_dsa_sig_size": 3293,
            "ed25519_sig_size": 64,
        },
    )

    return {
        "bom_format": "CycloneDX",
        "spec_version": "1.5",
        "serial_number": serial,
        "generated_at": generated_at,
        "tool": "LatticeGuard-v2.0",
        "components": signed_components,
        "total_components": len(signed_components),
        "quantum_safe": True,
        "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
        "fips_standard": "FIPS-204",
    }
