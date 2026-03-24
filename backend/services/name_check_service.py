"""
Phase 1 — Pre-Fetch Safety Gate
Fetches top-8,000 PyPI packages, signs the list with ML-DSA-65 + Ed25519,
and runs Levenshtein + homoglyph name verification before any PyPI calls.
"""
import time
import json
import hashlib
from typing import Optional
from dataclasses import dataclass

import httpx

TOP_PYPI_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)
CACHE_TTL = 86400  # 24 hours

# ── Cache state ────────────────────────────────────────────────────────────────
_cached_names: set = set()
_cached_names_list: list = []
_cached_names_by_len: dict = {}       # len → list[name] for fast Levenshtein
_cache_fetched_at: float = 0.0
_cache_ml_dsa_sig: bytes = b""
_cache_ed25519_sig: bytes = b""
_cache_canonical: bytes = b""

# ── Homoglyph normalisation ────────────────────────────────────────────────────
_HOMOGLYPHS = [("0", "o"), ("1", "l")]


def _normalize(s: str) -> str:
    s = s.lower().replace("rn", "m").replace("vv", "w")
    for orig, repl in _HOMOGLYPHS:
        s = s.replace(orig, repl)
    return s


# ── Levenshtein with early exit ────────────────────────────────────────────────
def _lev(a: str, b: str, max_d: int = 2) -> int:
    """Return Levenshtein distance, or max_d+1 if the distance exceeds max_d."""
    m, n = len(a), len(b)
    if abs(m - n) > max_d:
        return max_d + 1
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        row_min = i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            row_min = min(row_min, dp[j])
            prev = temp
        if row_min > max_d:
            return max_d + 1
    return dp[n]


# ── Padding pattern detection ──────────────────────────────────────────────────
_PADDING_PREFIXES = ["python-", "py-", "get-"]
_PADDING_SUFFIXES = ["-lib", "-python", "-py"]


def _check_padding(name: str, known: set) -> Optional[str]:
    n = name.lower()
    for prefix in _PADDING_PREFIXES:
        if n.startswith(prefix) and n[len(prefix):] in known:
            return n[len(prefix):]
    for suffix in _PADDING_SUFFIXES:
        if n.endswith(suffix) and n[: -len(suffix)] in known:
            return n[: -len(suffix)]
    return None


# ── List fetching + signing ────────────────────────────────────────────────────
async def _fetch_and_sign() -> None:
    global _cached_names, _cached_names_list, _cached_names_by_len
    global _cache_fetched_at, _cache_ml_dsa_sig, _cache_ed25519_sig, _cache_canonical

    from store.system_keystore import system_keystore
    from store.audit_store import audit_store
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    names: list = []
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(TOP_PYPI_URL)
            resp.raise_for_status()
            data = resp.json()
            names = [row["project"].lower() for row in data.get("rows", [])][:8000]
    except Exception:
        # On failure keep empty list — checks return UNKNOWN
        pass

    canonical_obj = {
        "source": TOP_PYPI_URL,
        "fetched_at": time.time(),
        "count": len(names),
        "names": sorted(names),
    }
    canonical = json.dumps(canonical_obj, sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()

    ml_sig = system_keystore.ml_dsa_signer.sign(digest)
    ed_sig = system_keystore.ed25519_private_key.sign(digest)

    # Build length-indexed lookup for fast Levenshtein
    by_len: dict = {}
    for n in names:
        by_len.setdefault(len(n), []).append(n)

    _cached_names = set(names)
    _cached_names_list = names
    _cached_names_by_len = by_len
    _cache_fetched_at = time.time()
    _cache_ml_dsa_sig = ml_sig
    _cache_ed25519_sig = ed_sig
    _cache_canonical = canonical

    audit_store.add_event(
        "NAME_LIST_FETCHED",
        f"Top-{len(names)} PyPI package list fetched and signed with ML-DSA-65 + Ed25519",
        {
            "count": len(names),
            "source": TOP_PYPI_URL,
            "ml_dsa_sig_bytes": len(ml_sig),
            "ml_dsa_sig_preview": ml_sig.hex()[:32] + "…",
            "ed25519_sig_preview": ed_sig.hex()[:16] + "…",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        },
    )


def _verify_list_integrity() -> bool:
    """Verify ML-DSA signature on the cached list before every name check."""
    if not _cache_canonical or not _cache_ml_dsa_sig:
        return False
    from store.system_keystore import system_keystore
    digest = hashlib.sha256(_cache_canonical).digest()
    try:
        return system_keystore.ml_dsa_signer.verify(
            digest, _cache_ml_dsa_sig, system_keystore.ml_dsa_public_key
        )
    except Exception:
        return False


async def ensure_ready() -> None:
    """Ensure list is loaded and not expired."""
    if time.time() - _cache_fetched_at > CACHE_TTL or not _cached_names:
        await _fetch_and_sign()


# ── Name check result ──────────────────────────────────────────────────────────
@dataclass
class NameCheckResult:
    package_name: str
    normalized_name: str
    verdict: str          # VERIFIED | LIKELY_TYPOSQUAT | SUSPICIOUS | UNKNOWN
    confidence: float     # 0.0 – 1.0
    nearest_match: Optional[str]
    edit_distance: Optional[int]
    list_size: int
    list_integrity_ok: bool
    ml_dsa_signature: str
    ed25519_signature: str
    public_key_ml_dsa: str
    public_key_ed25519: str
    checked_at: float

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "normalized_name": self.normalized_name,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "nearest_match": self.nearest_match,
            "edit_distance": self.edit_distance,
            "list_size": self.list_size,
            "list_integrity_ok": self.list_integrity_ok,
            "ml_dsa_signature": self.ml_dsa_signature,
            "ed25519_signature": self.ed25519_signature,
            "public_key_ml_dsa": self.public_key_ml_dsa,
            "public_key_ed25519": self.public_key_ed25519,
            "checked_at": self.checked_at,
            "ml_dsa_sig_bytes": 3293,
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        }


async def check_name(name: str) -> NameCheckResult:
    await ensure_ready()

    from store.system_keystore import system_keystore
    from store.audit_store import audit_store
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    integrity_ok = _verify_list_integrity()

    normalized = _normalize(name)
    name_lower = name.lower()

    verdict = "UNKNOWN"
    confidence = 0.5
    nearest_match: Optional[str] = None
    edit_distance: Optional[int] = None

    if _cached_names:
        # 1. Exact match (O(1))
        if name_lower in _cached_names or normalized in _cached_names:
            verdict = "VERIFIED"
            confidence = 1.0
        else:
            # 2. Padding pattern check
            pad = _check_padding(name_lower, _cached_names)
            if pad:
                verdict = "SUSPICIOUS"
                confidence = 0.3
                nearest_match = pad
            else:
                # 3. Levenshtein — only scan packages of similar length
                qlen = len(normalized)
                candidates: list = []
                for delta in range(3):  # lengths qlen, qlen±1, qlen±2
                    candidates += _cached_names_by_len.get(qlen + delta, [])
                    if delta > 0:
                        candidates += _cached_names_by_len.get(qlen - delta, [])

                best_dist = 99
                best_match_name = None
                for known in candidates:
                    d = _lev(normalized, known, max_d=2)
                    if d < best_dist:
                        best_dist = d
                        best_match_name = known
                        if d == 0:
                            break

                if best_dist == 0:
                    verdict = "VERIFIED"
                    confidence = 1.0
                elif best_dist == 1:
                    verdict = "LIKELY_TYPOSQUAT"
                    confidence = 0.1
                    nearest_match = best_match_name
                    edit_distance = best_dist
                elif best_dist == 2:
                    verdict = "SUSPICIOUS"
                    confidence = 0.3
                    nearest_match = best_match_name
                    edit_distance = best_dist
                else:
                    verdict = "UNKNOWN"
                    confidence = 0.6

    # Sign the verdict
    verdict_obj = {
        "package_name": name,
        "verdict": verdict,
        "confidence": confidence,
        "nearest_match": nearest_match,
        "edit_distance": edit_distance,
        "checked_at": time.time(),
    }
    canonical = json.dumps(verdict_obj, sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()

    ml_sig = system_keystore.ml_dsa_signer.sign(digest)
    ed_sig = system_keystore.ed25519_private_key.sign(digest)
    ed_pub = system_keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    audit_store.add_event(
        "NAME_CHECK",
        f'Package "{name}" verified — verdict: {verdict}',
        {
            "package": name,
            "verdict": verdict,
            "nearest_match": nearest_match,
            "edit_distance": edit_distance,
            "list_integrity_ok": integrity_ok,
            "ml_dsa_sig_preview": ml_sig.hex()[:32] + "…",
        },
    )

    return NameCheckResult(
        package_name=name,
        normalized_name=normalized,
        verdict=verdict,
        confidence=confidence,
        nearest_match=nearest_match,
        edit_distance=edit_distance,
        list_size=len(_cached_names),
        list_integrity_ok=integrity_ok,
        ml_dsa_signature=ml_sig.hex(),
        ed25519_signature=ed_sig.hex(),
        public_key_ml_dsa=system_keystore.ml_dsa_public_key.hex(),
        public_key_ed25519=ed_pub.hex(),
        checked_at=time.time(),
    )
