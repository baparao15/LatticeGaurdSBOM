import httpx
from models.schemas import CVE

OSV_URL = "https://api.osv.dev/v1/query"


async def check_vulnerabilities(name: str, version: str, ecosystem: str) -> list:
    ecosystem_map = {"pypi": "PyPI", "npm": "npm"}
    osv_ecosystem = ecosystem_map.get(ecosystem, "PyPI")

    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": osv_ecosystem},
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(OSV_URL, json=payload)
            if response.status_code != 200:
                return []

            data = response.json()
            vulns = data.get("vulns", [])
            result = []

            for vuln in vulns[:5]:
                fixed_in = None
                for affected in vuln.get("affected", []):
                    for r in affected.get("ranges", []):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_in = event["fixed"]

                severity = "UNKNOWN"
                for sev in vuln.get("severity", []):
                    severity = sev.get("type", "UNKNOWN")

                result.append(CVE(
                    id=vuln.get("id", ""),
                    severity=severity,
                    summary=(vuln.get("summary") or "")[:200],
                    fixed_in=fixed_in,
                    published=vuln.get("published") or "",
                ))

            return result
    except Exception:
        return []
