import httpx
import re
from models.schemas import Component, PackageFile

PYPI_BASE = "https://pypi.org/pypi"


def _classify_file(filename: str, packagetype: str = "") -> str:
    if filename.endswith(".whl"):
        return "wheel"
    if packagetype == "bdist_wheel":
        return "wheel"
    if filename.endswith(".tar.gz") or filename.endswith(".tar.bz2"):
        return "sdist"
    if filename.endswith(".zip") and packagetype == "sdist":
        return "sdist"
    if filename.endswith(".egg"):
        return "egg"
    if filename.endswith(".exe") or filename.endswith(".msi"):
        return "installer"
    return "other"


def _parse_wheel_tags(filename: str) -> dict:
    """Parse wheel filename to extract python/abi/platform tags.

    Wheel format (PEP 427):
      {distribution}-{version}(-{build})?-{python_tag}-{abi_tag}-{platform_tag}.whl
    The last three dash-separated fields (before .whl) are always the three tags.
    """
    if not filename.endswith(".whl"):
        return {}

    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) < 5:
        return {}

    platform_tag = parts[-1]
    abi_tag = parts[-2]
    python_tag = parts[-3]

    # OS from platform_tag
    if "manylinux" in platform_tag or "musllinux" in platform_tag or platform_tag.startswith("linux"):
        platform_os = "linux"
    elif "macosx" in platform_tag or "darwin" in platform_tag:
        platform_os = "macos"
    elif platform_tag.startswith("win"):
        platform_os = "windows"
    elif platform_tag == "any":
        platform_os = "any"
    else:
        platform_os = "other"

    # Architecture from platform_tag
    pt_lower = platform_tag.lower()
    if "x86_64" in pt_lower or "amd64" in pt_lower:
        platform_arch = "x86_64"
    elif "arm64" in pt_lower or "aarch64" in pt_lower:
        platform_arch = "arm64"
    elif "i686" in pt_lower or "win32" in pt_lower:
        platform_arch = "x86"
    else:
        platform_arch = "any"

    return {
        "python_tag": python_tag,
        "abi_tag": abi_tag,
        "platform_tag": platform_tag,
        "platform_os": platform_os,
        "platform_arch": platform_arch,
    }


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

        url_files = data.get("urls", [])

        # Collect ALL files with classification and parsed wheel tags
        package_files: list[PackageFile] = []
        seen_filenames = set()
        for fi in url_files:
            fname = fi["filename"]
            if fname in seen_filenames:
                continue
            seen_filenames.add(fname)
            ftype = _classify_file(fname, fi.get("packagetype", ""))
            wheel_tags = _parse_wheel_tags(fname) if ftype == "wheel" else {}
            pf = PackageFile(
                filename=fname,
                file_type=ftype,
                size_bytes=fi["size"],
                sha256=fi["digests"]["sha256"],
                python_version=fi.get("python_version") or None,
                requires_python=fi.get("requires_python") or None,
                python_tag=wheel_tags.get("python_tag"),
                abi_tag=wheel_tags.get("abi_tag"),
                platform_tag=wheel_tags.get("platform_tag"),
                platform_os=wheel_tags.get("platform_os"),
                platform_arch=wheel_tags.get("platform_arch"),
            )
            package_files.append(pf)

        # Unique file types present
        file_types_set: list[str] = []
        for pf in package_files:
            if pf.file_type not in file_types_set:
                file_types_set.append(pf.file_type)

        # Primary hash: prefer wheel, then first file
        for pf in package_files:
            if pf.file_type == "wheel":
                sha256 = pf.sha256
                size = pf.size_bytes
                for fi in url_files:
                    if fi["filename"] == pf.filename:
                        upload_date = fi.get("upload_time", "")
                break

        if not sha256 and package_files:
            sha256 = package_files[0].sha256
            size = package_files[0].size_bytes
            for fi in url_files:
                if fi["filename"] == package_files[0].filename:
                    upload_date = fi.get("upload_time", "")

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
            file_count=len(package_files),
            file_types=file_types_set,
            files=package_files,
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
