from pydantic import BaseModel
from typing import Optional, List


class PackageQuery(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str


class DependencyInput(BaseModel):
    raw_text: str
    ecosystem: str
    resolve_transitive: bool = True


class ManualPackageInput(BaseModel):
    packages: List[PackageQuery]


class Component(BaseModel):
    name: str
    version: str
    ecosystem: str
    purl: str
    description: str
    author: str
    license: str
    homepage: str
    sha256: str
    size_bytes: int
    upload_date: str
    dependencies: List[str]
    depth: int = 0


class CVE(BaseModel):
    id: str
    severity: str
    summary: str
    fixed_in: Optional[str] = None
    published: str


class SignedComponent(BaseModel):
    component: Component
    sha256_signed: str
    ed25519_signature: str
    ml_dsa_signature: str
    public_key_ed25519: str
    public_key_ml_dsa: str
    algorithm: str = "Hybrid(Ed25519 + ML-DSA-65)"
    fips_standard: str = "FIPS-204"
    security_level: str = "NIST-Level-3"
    signed_at: str
    signature_size_bytes: int
    cves: List[CVE] = []


class SBOM(BaseModel):
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    serial_number: str
    generated_at: str
    tool: str = "LatticeGuard-v1.0"
    components: List[SignedComponent]
    total_components: int
    total_vulnerabilities: int
    quantum_safe: bool = True
    signing_algorithm: str = "ML-DSA-65"
