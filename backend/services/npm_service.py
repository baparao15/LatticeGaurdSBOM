import httpx
from models.schemas import Component

NPM_BASE = "https://registry.npmjs.org"


async def fetch_package(name: str, version: str = None) -> Component:
    async with httpx.AsyncClient(timeout=15.0) as client:
        url = f"{NPM_BASE}/{name}"
        response = await client.get(url)

        if response.status_code == 404:
            raise ValueError(f"Package '{name}' not found on npm")

        data = response.json()
        dist_tags = data.get("dist-tags", {})
        versions = data.get("versions", {})
        latest = dist_tags.get("latest", "")

        if version and version not in versions:
            available = list(versions.keys())[-10:]
            raise ValueError(
                f"Version {version} of {name} does not exist on npm. "
                f"Available versions (latest 10): {available}"
            )

        target_version = version or latest
        version_data = versions.get(target_version, {})
        dist = version_data.get("dist", {})

        shasum = dist.get("shasum", "")
        deps = list(version_data.get("dependencies", {}).keys())

        author_raw = data.get("author", {})
        if isinstance(author_raw, dict):
            author = author_raw.get("name", "Unknown")
        elif isinstance(author_raw, str):
            author = author_raw
        else:
            author = "Unknown"

        return Component(
            name=data["name"],
            version=target_version,
            ecosystem="npm",
            purl=f"pkg:npm/{name}@{target_version}",
            description=(data.get("description") or "")[:300],
            author=author,
            license=version_data.get("license") or "Unknown",
            homepage=data.get("homepage") or "",
            sha256=shasum,
            size_bytes=dist.get("unpackedSize", 0),
            upload_date=data.get("time", {}).get(target_version, ""),
            dependencies=deps[:20],
            depth=0,
        )
