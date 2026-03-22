from fastapi import APIRouter
from services.osv_service import check_vulnerabilities

router = APIRouter()


@router.get("/check")
async def check_vuln(name: str, version: str, ecosystem: str = "pypi"):
    cves = await check_vulnerabilities(name, version, ecosystem)
    return {
        "package": name,
        "version": version,
        "ecosystem": ecosystem,
        "cves": [c.model_dump() for c in cves],
        "total": len(cves),
    }
