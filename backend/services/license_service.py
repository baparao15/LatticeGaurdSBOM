"""
Phase 6 — License Compliance Engine
Maps license strings to SPDX identifiers and flags incompatibilities:
  - Copyleft contamination (GPL in MIT project)
  - AGPL in any project (SaaS backend exposure)
  - Multiple/ambiguous licenses on one package
"""
import time
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# ── SPDX identifier map ────────────────────────────────────────────────────────
_SPDX_MAP: Dict[str, str] = {
    # MIT
    "mit": "MIT",
    "mit license": "MIT",
    "mit/x11": "MIT",
    # Apache
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    # BSD
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause",
    # GPL
    "gpl": "GPL-3.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    # LGPL
    "lgpl": "LGPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    # AGPL
    "agpl": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 (agplv3)": "AGPL-3.0-only",
    "agpl-3.0 license": "AGPL-3.0-only",
    # MPL
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    # ISC
    "isc": "ISC",
    "isc license": "ISC",
    # Python
    "psfl": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    # CC0 / Public domain
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "public domain": "CC0-1.0",
    "unlicense": "Unlicense",
    # EUPL
    "eupl-1.1": "EUPL-1.1",
    "eupl-1.2": "EUPL-1.2",
    # Proprietary
    "proprietary": "LicenseRef-Proprietary",
    "commercial": "LicenseRef-Proprietary",
    # Unknown
    "unknown": "NOASSERTION",
    "": "NOASSERTION",
}

_COPYLEFT = {
    "GPL-2.0-only", "GPL-3.0-only",
    "LGPL-2.1-only", "LGPL-3.0-only",
    "AGPL-3.0-only",
}
_AGPL = {"AGPL-3.0-only"}
_PERMISSIVE = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "PSF-2.0", "CC0-1.0", "Unlicense", "MPL-2.0",
}


def _to_spdx(raw: str) -> str:
    if not raw or raw.lower() in ("unknown", "none", ""):
        return "NOASSERTION"
    return _SPDX_MAP.get(raw.strip().lower(), f"LicenseRef-{raw[:40]}")


@dataclass
class LicenseFinding:
    package_name: str
    version: str
    license_raw: str
    spdx_id: str
    issues: List[str] = field(default_factory=list)
    is_copyleft: bool = False
    is_agpl: bool = False
    is_ambiguous: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "license_raw": self.license_raw,
            "spdx_id": self.spdx_id,
            "issues": self.issues,
            "is_copyleft": self.is_copyleft,
            "is_agpl": self.is_agpl,
            "is_ambiguous": self.is_ambiguous,
        }


@dataclass
class LicenseReport:
    packages: List[LicenseFinding]
    has_copyleft: bool
    has_agpl: bool
    has_ambiguous: bool
    compatibility_issues: List[str]
    ml_dsa_signature: str = ""
    ed25519_signature: str = ""
    public_key_ml_dsa: str = ""
    public_key_ed25519: str = ""
    generated_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packages": [p.to_dict() for p in self.packages],
            "total_packages": len(self.packages),
            "has_copyleft": self.has_copyleft,
            "has_agpl": self.has_agpl,
            "has_ambiguous": self.has_ambiguous,
            "compatibility_issues": self.compatibility_issues,
            "ml_dsa_signature": self.ml_dsa_signature,
            "ed25519_signature": self.ed25519_signature,
            "public_key_ml_dsa": self.public_key_ml_dsa,
            "public_key_ed25519": self.public_key_ed25519,
            "generated_at": self.generated_at,
            "ml_dsa_sig_bytes": 3293,
            "algorithm": "Hybrid(Ed25519 + ML-DSA-65)",
            "fips_standard": "FIPS-204",
            "security_level": "NIST-Level-3",
        }


async def analyze_licenses(
    packages: List[Dict[str, Any]],  # list of {name, version, license}
) -> LicenseReport:
    from store.system_keystore import system_keystore
    from store.audit_store import audit_store
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    findings: List[LicenseFinding] = []
    compat_issues: List[str] = []

    has_permissive = False
    has_copyleft = False
    has_agpl = False
    has_ambiguous = False

    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        raw_license = pkg.get("license", "") or ""

        # Handle " AND ", " OR " multi-license strings
        is_ambiguous = (
            " and " in raw_license.lower()
            or " or " in raw_license.lower()
            or ";" in raw_license
        )

        spdx = _to_spdx(raw_license)
        issues: List[str] = []

        is_copyleft = spdx in _COPYLEFT
        is_agpl = spdx in _AGPL
        is_permissive = spdx in _PERMISSIVE

        if is_agpl:
            issues.append(
                "AGPL-3.0: requires open-sourcing your application even for SaaS backends"
            )
            has_agpl = True
        if is_copyleft and not is_agpl:
            issues.append(
                f"{spdx}: copyleft — if combined with permissive-licensed code, "
                "the entire project may need to be released under this license"
            )

        if is_ambiguous:
            issues.append(
                f'Ambiguous license string "{raw_license}" — multiple licenses detected; '
                "legal review recommended"
            )
            has_ambiguous = True

        if spdx == "NOASSERTION":
            issues.append("License not declared — assume All Rights Reserved until clarified")

        if is_permissive:
            has_permissive = True
        if is_copyleft:
            has_copyleft = True

        findings.append(
            LicenseFinding(
                package_name=name,
                version=version,
                license_raw=raw_license,
                spdx_id=spdx,
                issues=issues,
                is_copyleft=is_copyleft,
                is_agpl=is_agpl,
                is_ambiguous=is_ambiguous,
            )
        )

    # Project-level compatibility issues
    if has_copyleft and has_permissive:
        compat_issues.append(
            "Copyleft contamination risk: GPL/LGPL-licensed packages are mixed with "
            "permissively-licensed packages. Depending on how they are linked, the "
            "entire project may be subject to copyleft terms."
        )
    if has_agpl:
        compat_issues.append(
            "AGPL-3.0 present: any networked use of this software may require you to "
            "release the complete source code — even for SaaS applications."
        )

    # Sign the report
    report_obj = {
        "package_count": len(findings),
        "has_copyleft": has_copyleft,
        "has_agpl": has_agpl,
        "has_ambiguous": has_ambiguous,
        "generated_at": time.time(),
    }
    canonical = json.dumps(report_obj, sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()

    ml_sig = system_keystore.ml_dsa_signer.sign(digest)
    ed_sig = system_keystore.ed25519_private_key.sign(digest)
    ed_pub = system_keystore.ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    audit_store.add_event(
        "LICENSE_ANALYSIS",
        f"License analysis complete: {len(findings)} packages, "
        f"copyleft={has_copyleft}, agpl={has_agpl}, ambiguous={has_ambiguous}",
        {
            "package_count": len(findings),
            "has_copyleft": has_copyleft,
            "has_agpl": has_agpl,
            "has_ambiguous": has_ambiguous,
            "issue_count": sum(len(f.issues) for f in findings),
        },
    )

    return LicenseReport(
        packages=findings,
        has_copyleft=has_copyleft,
        has_agpl=has_agpl,
        has_ambiguous=has_ambiguous,
        compatibility_issues=compat_issues,
        ml_dsa_signature=ml_sig.hex(),
        ed25519_signature=ed_sig.hex(),
        public_key_ml_dsa=system_keystore.ml_dsa_public_key.hex(),
        public_key_ed25519=ed_pub.hex(),
        generated_at=time.time(),
    )
