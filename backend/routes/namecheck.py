"""
Route: /latticeguard-api/namecheck
Phase 1 — Pre-Fetch Safety Gate
"""
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from services.name_check_service import check_name, ensure_ready

router = APIRouter()


class NameCheckRequest(BaseModel):
    names: List[str]


@router.post("/batch")
async def batch_check_names(req: NameCheckRequest):
    """Check multiple package names before any PyPI fetch — returns signed verdicts."""
    await ensure_ready()
    results = await asyncio.gather(*[check_name(name) for name in req.names[:100]])
    return {
        "results": [r.to_dict() for r in results],
        "total": len(results),
    }


@router.post("/check")
async def check_single_name(req: BaseModel):
    """Check a single package name."""
    await ensure_ready()
    name = getattr(req, "name", "")
    result = await check_name(name)
    return result.to_dict()


@router.get("/status")
async def list_status():
    """Return the name list cache status."""
    from services.name_check_service import (
        _cached_names,
        _cache_fetched_at,
        _verify_list_integrity,
    )
    import time
    return {
        "list_size": len(_cached_names),
        "cache_age_seconds": time.time() - _cache_fetched_at if _cache_fetched_at else None,
        "integrity_ok": _verify_list_integrity(),
        "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
        "fips_standard": "FIPS-204",
    }
