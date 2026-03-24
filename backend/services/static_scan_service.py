"""
Phase 3 — Static Source Scan
Downloads the sdist tar.gz from PyPI (without executing it), extracts it in memory,
and scans install-time files for malicious patterns.
"""
import io
import re
import time
import json
import tarfile
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import httpx


# ── Scan patterns ──────────────────────────────────────────────────────────────
@dataclass
class _Pattern:
    regex: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    # If None, applies to all files; otherwise only to these filenames
    file_filter: Optional[List[str]] = None


_PATTERNS: List[_Pattern] = [
    _Pattern(
        regex=r"exec\s*\(\s*base64\.b64decode\(",
        severity="CRITICAL",
        description="Obfuscated code execution via base64-decoded exec() — classic malware pattern",
    ),
    _Pattern(
        regex=r"eval\s*\(\s*base64\.b64decode\(",
        severity="CRITICAL",
        description="Obfuscated eval execution via base64 decode",
    ),
    _Pattern(
        regex=r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
        severity="HIGH",
        description="Subprocess execution in install script — code runs on `pip install`",
        file_filter=["setup.py", "setup.cfg", "pyproject.toml"],
    ),
    _Pattern(
        regex=r"os\.(system|popen|execve|execvp|execl|spawnl)\s*\(",
        severity="HIGH",
        description="OS command execution in install script",
        file_filter=["setup.py", "setup.cfg", "pyproject.toml"],
    ),
    _Pattern(
        regex=r"(urllib\.request|urllib\.urlopen|requests\.(get|post|put)|httpx\.)",
        severity="HIGH",
        description="Network call in install script — data exfiltration or payload download risk",
        file_filter=["setup.py", "setup.cfg", "pyproject.toml"],
    ),
    _Pattern(
        regex=r"socket\.(connect|socket|create_connection)\s*\(",
        severity="HIGH",
        description="Raw socket connection in install script",
        file_filter=["setup.py", "setup.cfg", "pyproject.toml"],
    ),
    _Pattern(
        regex=r"(AWS_|GITHUB_TOKEN|SSH_KEY|\.ssh[\\/]id_rsa|SECRET_KEY|API_KEY|PRIVATE_KEY)",
        severity="CRITICAL",
        description="Credential harvesting pattern — scans for cloud keys or SSH private keys",
    ),
    _Pattern(
        regex=r"(import ctypes|from ctypes import)",
        severity="MEDIUM",
        description="Native code injection via ctypes — can bypass Python sandboxing",
        file_filter=["setup.py", "__init__.py"],
    ),
    _Pattern(
        regex=r"(import cffi|from cffi import)",
        severity="MEDIUM",
        description="Native code injection via cffi",
        file_filter=["setup.py", "__init__.py"],
    ),
    _Pattern(
        regex=r"__import__\s*\(\s*['\"]os['\"]",
        severity="HIGH",
        description="Dynamic OS import — attempt to hide os module usage",
    ),
    _Pattern(
        regex=r"compile\s*\(\s*base64",
        severity="HIGH",
        description="Compiling base64-encoded code — obfuscation technique",
    ),
]

# Files to scan (always included if present)
_ALWAYS_SCAN = {"setup.py", "setup.cfg", "pyproject.toml"}
# Also scan all __init__.py files


@dataclass
class StaticFinding:
    pattern: str
    file: str
    line_number: int
    severity: str
    description: str
    line_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "file": self.file,
            "line_number": self.line_number,
            "severity": self.severity,
            "description": self.description,
            "line_content": self.line_content[:200],  # truncate for safety
        }


@dataclass
class StaticScanResult:
    package_name: str
    version: str
    sdist_url: str
    findings: List[StaticFinding] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    error: Optional[str] = None
    scanned_at: float = 0.0
    ml_dsa_signature: str = ""
    ed25519_signature: str = ""
    public_key_ml_dsa: str = ""
    public_key_ed25519: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "sdist_url": self.sdist_url,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "scanned_files": self.scanned_files,
            "error": self.error,
            "scanned_at": self.scanned_at,
            "ml_dsa_signature": self.ml_dsa_signature,
            "ed25519_signature": self.ed25519_signature,
            "public_key_ml_dsa": self.public_key_ml_dsa,
            "public_key_ed25519": self.public_key_ed25519,
            "ml_dsa_sig_bytes": 3293,
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        }


def _should_scan(filename: str, pat: _Pattern) -> bool:
    basename = filename.rsplit("/", 1)[-1]
    if pat.file_filter is None:
        return True
    return basename in pat.file_filter


def _scan_content(filename: str, content: str) -> List[StaticFinding]:
    findings: List[StaticFinding] = []
    lines = content.splitlines()
    for pat in _PATTERNS:
        if not _should_scan(filename, pat):
            continue
        regex = re.compile(pat.regex, re.IGNORECASE)
        for lineno, line in enumerate(lines, start=1):
            if regex.search(line):
                findings.append(
                    StaticFinding(
                        pattern=pat.regex,
                        file=filename,
                        line_number=lineno,
                        severity=pat.severity,
                        description=pat.description,
                        line_content=line.strip(),
                    )
                )
    return findings


async def scan_package(
    package_name: str,
    version: str,
    sdist_url: str,
) -> StaticScanResult:
    from store.system_keystore import system_keystore
    from store.audit_store import audit_store
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    findings: List[StaticFinding] = []
    scanned_files: List[str] = []
    error: Optional[str] = None

    try:
        # Download sdist (max 20 MB, 15s timeout)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(sdist_url, follow_redirects=True)
            resp.raise_for_status()
            raw = resp.content
            if len(raw) > 20 * 1024 * 1024:
                error = "sdist too large (>20 MB) — skipped"
            else:
                # Extract and scan in memory
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                    for member in tf.getmembers():
                        basename = member.name.rsplit("/", 1)[-1]
                        is_target = (
                            basename in _ALWAYS_SCAN
                            or (basename == "__init__.py")
                        )
                        if not is_target or not member.isfile():
                            continue
                        try:
                            f = tf.extractfile(member)
                            if f is None:
                                continue
                            content = f.read().decode("utf-8", errors="replace")
                            scanned_files.append(member.name)
                            findings.extend(_scan_content(member.name, content))
                        except Exception:
                            pass
    except Exception as e:
        error = str(e)[:200]

    # Sign the result
    result_obj = {
        "package_name": package_name,
        "version": version,
        "finding_count": len(findings),
        "scanned_at": time.time(),
    }
    canonical = json.dumps(result_obj, sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()

    ml_sig = system_keystore.ml_dsa_signer.sign(digest)
    ed_sig = system_keystore.ed25519_private_key.sign(digest)
    ed_pub = system_keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    audit_store.add_event(
        "STATIC_SCAN",
        f"Static scan of {package_name}@{version}: {len(findings)} finding(s) in {len(scanned_files)} file(s)",
        {
            "package": package_name,
            "version": version,
            "finding_count": len(findings),
            "scanned_files": scanned_files,
            "error": error,
            "ml_dsa_sig_preview": ml_sig.hex()[:32] + "…",
        },
    )

    return StaticScanResult(
        package_name=package_name,
        version=version,
        sdist_url=sdist_url,
        findings=findings,
        scanned_files=scanned_files,
        error=error,
        scanned_at=time.time(),
        ml_dsa_signature=ml_sig.hex(),
        ed25519_signature=ed_sig.hex(),
        public_key_ml_dsa=system_keystore.ml_dsa_public_key.hex(),
        public_key_ed25519=ed_pub.hex(),
    )
