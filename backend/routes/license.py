"""
Route: /latticeguard-api/license
Phase 6 — License Compliance Engine
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from services.license_service import analyze_licenses

router = APIRouter()


class PackageLicenseInfo(BaseModel):
    name: str
    version: str
    license: Optional[str] = ""


class LicenseAnalysisRequest(BaseModel):
    packages: List[PackageLicenseInfo]


@router.post("/analyze")
async def analyze(req: LicenseAnalysisRequest):
    """Analyze license compatibility across all packages."""
    pkg_dicts = [
        {"name": p.name, "version": p.version, "license": p.license or ""}
        for p in req.packages
    ]
    report = await analyze_licenses(pkg_dicts)
    return report.to_dict()
