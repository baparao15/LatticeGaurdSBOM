import httpx
import re
from models.schemas import Component

PYPI_BASE = "https://pypi.org/pypi"


async def fetch_package(name: str, version: str = None) -> Component:
    async with httpx.AsyncClient(timeout=15.0) as client:
        if version:
            url = f"{PYPI_BASE}/{name}/{version}/json"
        else:
            url = f"{PYPI_BASE}/{name}/json"

        response = await client.get(url)

        if response.status_code == 404:
            all_resp = await client.get(f"{PYPI_BASE}/{name}/json")
            if all_resp.status_code == 200:
                all_data = all_resp.json()
                available = list(all_data["releases"].keys())

                def _ver_key(v):
                    nums = []
                    for p in v.split("."):
                        try:
                            nums.append(int(p))
                        except ValueError:
                            nums.append(0)
                    return nums

                available_sorted = sorted(
                    [v for v in available if all_data["releases"][v]],
                    key=_ver_key,
                    reverse=True,
                )[:10]
                raise ValueError(
                    f"Version {version} of {name} does not exist on PyPI. "
                    f"Available versions: {available_sorted}"
                )
            raise ValueError(f"Package '{name}' not found on PyPI")

        data = response.json()
        info = data["info"]

        sha256 = ""
        size = 0
        upload_date = ""

        # When fetching a specific version, PyPI returns the dist files in
        # data["urls"] — NOT in data["releases"][version] (which is empty).
        # When fetching latest (no version), files are in data["urls"] too.
        url_files = data.get("urls", [])

        # Prefer wheel, fall back to sdist
        for file_info in url_files:
            if file_info["filename"].endswith(".whl"):
                sha256 = file_info["digests"]["sha256"]
                size = file_info["size"]
                upload_date = file_info.get("upload_time", "")
                break

        if not sha256 and url_files:
            file_info = url_files[0]
            sha256 = file_info["digests"]["sha256"]
            size = file_info["size"]
            upload_date = file_info.get("upload_time", "")

        requires = info.get("requires_dist") or []
        direct_deps = []
        for req in requires:
            if ";" not in req and "extra ==" not in req:
                dep_name = re.split(r"[><=!~\[\s]", req)[0].strip().lower()
                if dep_name:
                    direct_deps.append(dep_name)

        return Component(
            name=info["name"],
            version=info["version"],
            ecosystem="pypi",
            purl=f"pkg:pypi/{info['name']}@{info['version']}",
            description=(info.get("summary") or "")[:300],
            author=info.get("author") or info.get("maintainer") or "Unknown",
            license=info.get("license") or "Unknown",
            homepage=info.get("home_page") or info.get("project_url") or "",
            sha256=sha256,
            size_bytes=size,
            upload_date=upload_date,
            dependencies=direct_deps[:20],
            depth=0,
        )


async def resolve_transitive(
    name: str,
    version: str,
    visited: set = None,
    depth: int = 0,
) -> list:
    if visited is None:
        visited = set()

    if name.lower() in visited or depth > 3:
        return []

    visited.add(name.lower())
    tree = []

    try:
        component = await fetch_package(name, version)
        component.depth = depth

        for dep_name in component.dependencies[:8]:
            sub_deps = await resolve_transitive(dep_name, None, visited, depth + 1)
            tree.extend(sub_deps)

        tree.append(component)
    except Exception:
        pass

    return tree
