import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import packages, signing, verify, vulnerabilities, namecheck, risk, scan, license, audit


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-fetch the top-8K PyPI name list and sign it at startup
    try:
        from services.name_check_service import ensure_ready
        await ensure_ready()
    except Exception:
        pass  # Non-fatal — name checks will return UNKNOWN until list is loaded
    yield


app = FastAPI(title="LatticeGuard API v2", root_path="", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/latticeguard-api"

# Existing routes
app.include_router(packages.router,        prefix=f"{PREFIX}/packages")
app.include_router(signing.router,         prefix=f"{PREFIX}/sign")
app.include_router(verify.router,          prefix=f"{PREFIX}/verify")
app.include_router(vulnerabilities.router, prefix=f"{PREFIX}/vuln")

# New Phase 1-8 routes
app.include_router(namecheck.router, prefix=f"{PREFIX}/namecheck")
app.include_router(risk.router,      prefix=f"{PREFIX}/risk")
app.include_router(scan.router,      prefix=f"{PREFIX}/scan")
app.include_router(license.router,   prefix=f"{PREFIX}/license")
app.include_router(audit.router,     prefix=f"{PREFIX}/audit")


@app.get(f"{PREFIX}/health")
def health():
    from store.keystore import HAS_OQS
    from services.name_check_service import _cached_names, _cache_fetched_at
    import time
    return {
        "status": "LatticeGuard v2 running",
        "real_oqs": HAS_OQS,
        "algorithm": "ML-DSA-65 (FIPS 204)",
        "name_list_size": len(_cached_names),
        "name_list_age_seconds": time.time() - _cache_fetched_at if _cache_fetched_at else None,
        "phases": [
            "Phase 1: Pre-fetch name gate (ML-DSA signed top-8K list)",
            "Phase 2: Risk scoring (5-signal 0-100 score)",
            "Phase 3: Static source scan (sdist pattern detection)",
            "Phase 4: PQC Audit Log",
            "Phase 5: Quantum Threat Simulator (frontend)",
            "Phase 6: License Compliance Engine",
            "Phase 7: Enhanced 6-file SBOM export",
            "Phase 8: CI/CD Integration panel (frontend)",
        ],
    }
