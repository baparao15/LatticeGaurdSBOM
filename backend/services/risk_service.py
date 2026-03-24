"""
Phase 2 — Package Risk Scoring
Computes a 0-100 risk score from 5 independent signals:
  1. CVE severity (0-40 pts)
  2. Package age / activity (0-20 pts)
  3. Maintainer count estimate (0-15 pts)
  4. Download volume (0-15 pts)
  5. Name check result (0-10 pts)
"""
import time
import json
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import httpx


# ── CVE severity weights ───────────────────────────────────────────────────────
_CVE_WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}


def _cve_score(cves: List[Dict]) -> int:
    if not cves:
        return 0
    # Take the highest single CVE score (not additive — worst vulnerability drives the score)
    return min(40, max((_CVE_WEIGHTS.get(c.get("severity", "LOW"), 0) for c in cves), default=0))


# ── Age / activity scoring ─────────────────────────────────────────────────────
def _age_score(
    upload_date: str,
    first_release_date: Optional[str],
    release_count: int,
) -> int:
    score = 0
    now = time.time()

    # Check if first release is < 6 months ago
    ref_date = first_release_date or upload_date
    if ref_date:
        try:
            import datetime
            # PyPI dates: "2023-01-15T12:34:56" or "2023-01-15T12:34:56.789012"
            dt_str = ref_date.replace("Z", "").split(".")[0]
            dt = datetime.datetime.fromisoformat(dt_str)
            age_days = (datetime.datetime.utcnow() - dt).days
            if age_days < 180:
                score += 15
        except Exception:
            pass

    # Only 1 release ever
    if release_count == 1:
        score += 10
    elif release_count == 0:
        score += 5

    # No release in over 3 years (based on upload_date of this version)
    if upload_date:
        try:
            import datetime
            dt_str = upload_date.replace("Z", "").split(".")[0]
            dt = datetime.datetime.fromisoformat(dt_str)
            days_since = (datetime.datetime.utcnow() - dt).days
            if days_since > 1095:  # 3 years
                score += 10
        except Exception:
            pass

    return min(20, score)


# ── Maintainer count scoring ───────────────────────────────────────────────────
def _maintainer_score(maintainer_count: int) -> int:
    if maintainer_count <= 1:
        return 15
    elif maintainer_count <= 3:
        return 5
    return 0


# ── Download volume scoring ────────────────────────────────────────────────────
async def _fetch_monthly_downloads(package_name: str) -> Optional[int]:
    """Fetch monthly download count from pypistats.org."""
    url = f"https://pypistats.org/api/packages/{package_name.lower()}/recent"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {}).get("last_month")
    except Exception:
        pass
    return None


def _download_score(monthly_downloads: Optional[int]) -> int:
    if monthly_downloads is None:
        return 0  # Unknown — don't penalise
    if monthly_downloads < 1_000:
        return 15
    if monthly_downloads < 10_000:
        return 8
    return 0


# ── Name check scoring ─────────────────────────────────────────────────────────
def _name_score(verdict: str) -> int:
    return {"UNKNOWN": 5, "SUSPICIOUS": 10, "LIKELY_TYPOSQUAT": 10}.get(verdict, 0)


# ── Risk level label ───────────────────────────────────────────────────────────
def _risk_level(score: int) -> str:
    if score <= 25:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    return "HIGH"


# ── Result dataclass ───────────────────────────────────────────────────────────
@dataclass
class RiskScore:
    package_name: str
    version: str
    total_score: int
    risk_level: str
    cve_score: int
    age_score: int
    maintainer_score: int
    download_score: int
    name_score: int
    monthly_downloads: Optional[int]
    release_count: int
    signals: Dict[str, Any] = field(default_factory=dict)
    ml_dsa_signature: str = ""
    ed25519_signature: str = ""
    public_key_ml_dsa: str = ""
    public_key_ed25519: str = ""
    computed_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "breakdown": {
                "cve_score": self.cve_score,
                "age_score": self.age_score,
                "maintainer_score": self.maintainer_score,
                "download_score": self.download_score,
                "name_score": self.name_score,
            },
            "monthly_downloads": self.monthly_downloads,
            "release_count": self.release_count,
            "signals": self.signals,
            "ml_dsa_signature": self.ml_dsa_signature,
            "ed25519_signature": self.ed25519_signature,
            "public_key_ml_dsa": self.public_key_ml_dsa,
            "public_key_ed25519": self.public_key_ed25519,
            "computed_at": self.computed_at,
            "ml_dsa_sig_bytes": 3293,
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        }


async def compute_risk(
    package_name: str,
    version: str,
    ecosystem: str,
    cves: List[Dict],
    upload_date: str = "",
    first_release_date: Optional[str] = None,
    release_count: int = 0,
    maintainer: Optional[str] = None,
    name_verdict: str = "UNKNOWN",
    fetch_downloads: bool = True,
) -> RiskScore:
    from store.system_keystore import system_keystore
    from store.audit_store import audit_store
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Scores
    cs = _cve_score(cves)
    ag = _age_score(upload_date, first_release_date, release_count)

    # Maintainer count — 1 if maintainer is a non-empty string, otherwise unknown→default 1
    mc = 1 if (maintainer and maintainer.strip() and maintainer.lower() != "unknown") else 1
    ms = _maintainer_score(mc)

    # Download stats (only for PyPI)
    monthly_dl: Optional[int] = None
    if fetch_downloads and ecosystem == "pypi":
        monthly_dl = await _fetch_monthly_downloads(package_name)
    ds = _download_score(monthly_dl)

    ns = _name_score(name_verdict)

    total = min(100, cs + ag + ms + ds + ns)
    level = _risk_level(total)

    signals = {
        "cve_count": len(cves),
        "worst_cve_severity": max(
            (c.get("severity", "LOW") for c in cves),
            key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)
            if s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            else 0,
            default=None,
        ),
        "maintainer_count_estimated": mc,
        "monthly_downloads": monthly_dl,
        "name_verdict": name_verdict,
        "upload_date": upload_date,
        "first_release_date": first_release_date,
        "release_count": release_count,
    }

    # Sign the result
    score_obj = {
        "package_name": package_name,
        "version": version,
        "total_score": total,
        "risk_level": level,
        "computed_at": time.time(),
    }
    canonical = json.dumps(score_obj, sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()

    ml_sig = system_keystore.ml_dsa_signer.sign(digest)
    ed_sig = system_keystore.ed25519_private_key.sign(digest)
    ed_pub = system_keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    audit_store.add_event(
        "RISK_SCORED",
        f'Risk score computed for {package_name}@{version}: {total}/100 ({level})',
        {
            "package": package_name,
            "version": version,
            "total_score": total,
            "risk_level": level,
            "breakdown": {"cve": cs, "age": ag, "maintainer": ms, "downloads": ds, "name": ns},
            "ml_dsa_sig_preview": ml_sig.hex()[:32] + "…",
        },
    )

    return RiskScore(
        package_name=package_name,
        version=version,
        total_score=total,
        risk_level=level,
        cve_score=cs,
        age_score=ag,
        maintainer_score=ms,
        download_score=ds,
        name_score=ns,
        monthly_downloads=monthly_dl,
        release_count=release_count,
        signals=signals,
        ml_dsa_signature=ml_sig.hex(),
        ed25519_signature=ed_sig.hex(),
        public_key_ml_dsa=system_keystore.ml_dsa_public_key.hex(),
        public_key_ed25519=ed_pub.hex(),
        computed_at=time.time(),
    )
