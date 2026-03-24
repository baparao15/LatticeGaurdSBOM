"""
Route: /latticeguard-api/scan
Phase 3 — Static Source Scan
"""
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from services.static_scan_service import scan_package

router = APIRouter()


class ScanRequest(BaseModel):
    package_name: str
    version: str
    sdist_url: str


class ScanBatchRequest(BaseModel):
    packages: List[ScanRequest]


@router.post("/sdist")
async def scan_sdist(req: ScanRequest):
    """Scan a single sdist tar.gz for malicious patterns."""
    result = await scan_package(req.package_name, req.version, req.sdist_url)
    return result.to_dict()


@router.post("/sdist-batch")
async def scan_batch(req: ScanBatchRequest):
    """Scan multiple sdist files concurrently (max 10)."""
    limited = req.packages[:10]  # safety limit
    tasks = [scan_package(p.package_name, p.version, p.sdist_url) for p in limited]
    results = await asyncio.gather(*tasks)
    return {
        "results": [r.to_dict() for r in results],
        "total_scanned": len(results),
        "total_findings": sum(len(r.findings) for r in results),
        "critical_count": sum(
            1 for r in results for f in r.findings if f.severity == "CRITICAL"
        ),
        "high_count": sum(
            1 for r in results for f in r.findings if f.severity == "HIGH"
        ),
    }
