"""
Route: /latticeguard-api/risk
Phase 2 — Package Risk Scoring
"""
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from services.risk_service import compute_risk

router = APIRouter()


class RiskRequest(BaseModel):
    package_name: str
    version: str
    ecosystem: str = "pypi"
    cves: List[Dict[str, Any]] = []
    upload_date: str = ""
    first_release_date: Optional[str] = None
    release_count: int = 0
    maintainer: Optional[str] = None
    name_verdict: str = "UNKNOWN"


class RiskBatchRequest(BaseModel):
    packages: List[RiskRequest]


@router.post("/score")
async def score_risk(req: RiskRequest):
    result = await compute_risk(
        package_name=req.package_name,
        version=req.version,
        ecosystem=req.ecosystem,
        cves=req.cves,
        upload_date=req.upload_date,
        first_release_date=req.first_release_date,
        release_count=req.release_count,
        maintainer=req.maintainer,
        name_verdict=req.name_verdict,
    )
    return result.to_dict()


@router.post("/score-batch")
async def score_batch(req: RiskBatchRequest):
    """Score multiple packages concurrently."""
    tasks = [
        compute_risk(
            package_name=p.package_name,
            version=p.version,
            ecosystem=p.ecosystem,
            cves=p.cves,
            upload_date=p.upload_date,
            first_release_date=p.first_release_date,
            release_count=p.release_count,
            maintainer=p.maintainer,
            name_verdict=p.name_verdict,
        )
        for p in req.packages
    ]
    results = await asyncio.gather(*tasks)
    scores = [r.to_dict() for r in results]

    # Project-level aggregate
    if scores:
        avg = sum(s["total_score"] for s in scores) / len(scores)
        worst = max(scores, key=lambda s: s["total_score"])
    else:
        avg = 0
        worst = None

    return {
        "scores": scores,
        "total_packages": len(scores),
        "aggregate_score": round(avg),
        "worst_package": worst,
        "high_risk_count": sum(1 for s in scores if s["risk_level"] == "HIGH"),
        "medium_risk_count": sum(1 for s in scores if s["risk_level"] == "MEDIUM"),
        "low_risk_count": sum(1 for s in scores if s["risk_level"] == "LOW"),
    }
