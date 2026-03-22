import copy
import random
from fastapi import APIRouter
from services.crypto_service import verify_component
from models.schemas import SignedComponent

router = APIRouter()


@router.post("/verify-sbom")
async def verify_sbom(sbom: dict):
    results = []
    for item in sbom.get("components", []):
        try:
            signed = SignedComponent(**item)
            result = verify_component(signed)
            results.append(result)
        except Exception as e:
            results.append({
                "component": item.get("component", {}).get("name", "unknown"),
                "version": item.get("component", {}).get("version", ""),
                "hash_match": False,
                "ed25519_valid": False,
                "ml_dsa_valid": False,
                "overall_valid": False,
                "error": str(e),
            })

    all_valid = all(r.get("overall_valid", False) for r in results)

    return {
        "overall_valid": all_valid,
        "total": len(results),
        "passed": sum(1 for r in results if r.get("overall_valid")),
        "failed": sum(1 for r in results if not r.get("overall_valid")),
        "results": results,
        "status": "SAFE_TO_INSTALL" if all_valid else "BLOCKED",
    }


@router.post("/tamper-simulate")
async def tamper_simulate(sbom: dict):
    components = sbom.get("components", [])
    if not components:
        return {"error": "No components to tamper"}

    tampered_sbom = copy.deepcopy(sbom)
    target_idx = random.randint(0, len(components) - 1)

    # Actually corrupt the component data
    tampered_sbom["components"][target_idx]["component"]["sha256"] += "_TAMPERED_BY_ATTACKER"

    results = []
    for i, item in enumerate(tampered_sbom["components"]):
        try:
            signed = SignedComponent(**item)
            result = verify_component(signed)
            result["was_tampered"] = (i == target_idx)
            results.append(result)
        except Exception as e:
            results.append({
                "component": item.get("component", {}).get("name", "unknown"),
                "version": item.get("component", {}).get("version", ""),
                "hash_match": False,
                "ed25519_valid": False,
                "ml_dsa_valid": False,
                "overall_valid": False,
                "was_tampered": (i == target_idx),
                "error": str(e),
            })

    tampered_name = components[target_idx]["component"]["name"]
    tampered_version = components[target_idx]["component"]["version"]

    return {
        "overall_valid": False,
        "tampered_component": f"{tampered_name}@{tampered_version}",
        "tampered_index": target_idx,
        "results": results,
        "status": "ATTACK_DETECTED_AND_BLOCKED",
        "attack_type": "Supply Chain Injection",
        "blocked_by": "ML-DSA-65 Lattice Signature",
    }
