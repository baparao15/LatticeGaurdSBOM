import re
import json as jsonlib
from fastapi import APIRouter
from models.schemas import DependencyInput, ManualPackageInput
from services import pypi_service, npm_service, osv_service

router = APIRouter()


@router.post("/resolve")
async def resolve_dependencies(input: DependencyInput):
    components = []
    errors = []

    packages = []

    if input.ecosystem == "pypi":
        lines = input.raw_text.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r'^import\s+', '', line, flags=re.IGNORECASE)
            line = re.sub(r'^from\s+', '', line, flags=re.IGNORECASE)
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:[=><~!]+(.+))?', line)
            if match:
                name = match.group(1)
                version_spec = match.group(2)
                exact = None
                if version_spec and "==" in line:
                    exact = version_spec.strip().split(",")[0]
                packages.append((name, exact))

    elif input.ecosystem == "npm":
        try:
            pkg = jsonlib.loads(input.raw_text)
            deps = {
                **pkg.get("dependencies", {}),
                **pkg.get("devDependencies", {}),
            }
            packages = [
                (name, ver.lstrip("^~>=<"))
                for name, ver in deps.items()
            ]
        except Exception:
            for line in input.raw_text.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if "@" in line and not line.startswith("@"):
                    parts = line.split("@")
                    packages.append((parts[0], parts[1] if len(parts) > 1 else None))
                elif "@" in line and line.startswith("@"):
                    rest = line[1:]
                    parts = rest.split("@")
                    packages.append((f"@{parts[0]}", parts[1] if len(parts) > 1 else None))
                else:
                    packages.append((line.strip(), None))

    for name, version in packages:
        try:
            if input.ecosystem == "pypi":
                component = await pypi_service.fetch_package(name, version)
            else:
                component = await npm_service.fetch_package(name, version)

            cves = await osv_service.check_vulnerabilities(
                component.name, component.version, input.ecosystem
            )

            transitive = []
            if input.resolve_transitive and input.ecosystem == "pypi":
                transitive = await pypi_service.resolve_transitive(name, version)

            components.append({
                "component": component.model_dump(),
                "cves": [c.model_dump() for c in cves],
                "transitive_count": len(transitive),
                "transitive": [t.model_dump() for t in transitive],
            })

        except ValueError as e:
            errors.append({
                "package": name,
                "requested_version": version,
                "error": str(e),
                "type": "VERSION_NOT_FOUND",
            })
        except Exception as e:
            errors.append({
                "package": name,
                "error": str(e),
                "type": "FETCH_ERROR",
            })

    return {
        "components": components,
        "errors": errors,
        "total_found": len(components),
        "total_failed": len(errors),
    }


@router.post("/manual")
async def resolve_manual(input: ManualPackageInput):
    results = []
    for pkg in input.packages:
        try:
            if pkg.ecosystem == "pypi":
                component = await pypi_service.fetch_package(pkg.name, pkg.version)
            else:
                component = await npm_service.fetch_package(pkg.name, pkg.version)

            cves = await osv_service.check_vulnerabilities(
                component.name, component.version, pkg.ecosystem
            )
            results.append({
                "status": "found",
                "component": component.model_dump(),
                "cves": [c.model_dump() for c in cves],
            })
        except ValueError as e:
            # Parse available versions from the error message if present
            import re
            available = []
            match = re.search(r"Available versions[^:]*:\s*(\[.+?\])", str(e))
            if match:
                import ast
                try:
                    available = ast.literal_eval(match.group(1))
                except Exception:
                    pass
            results.append({
                "status": "error",
                "package": pkg.name,
                "message": str(e),
                "available_versions": available,
            })
        except Exception as e:
            results.append({
                "status": "error",
                "package": pkg.name,
                "message": str(e),
                "available_versions": [],
            })
    return results
