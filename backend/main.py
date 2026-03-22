import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import packages, signing, verify, vulnerabilities

app = FastAPI(title="LatticeGuard API", root_path="")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/latticeguard-api"

app.include_router(packages.router, prefix=f"{PREFIX}/packages")
app.include_router(signing.router, prefix=f"{PREFIX}/sign")
app.include_router(verify.router, prefix=f"{PREFIX}/verify")
app.include_router(vulnerabilities.router, prefix=f"{PREFIX}/vuln")


@app.get(f"{PREFIX}/health")
def health():
    from store.keystore import HAS_OQS
    return {
        "status": "LatticeGuard running",
        "real_oqs": HAS_OQS,
        "algorithm": "ML-DSA-65 (FIPS 204)",
    }
