import { api } from "./client";
import type { ResolvedPackage } from "./packages";

export interface KeygenResult {
  ml_dsa_public_key: string;
  ml_dsa_public_key_size: number;
  ed25519_public_key: string;
  algorithm: string;
  security_level: string;
  fips_standard: string;
  generated_at: number;
  using_real_oqs: boolean;
  message: string;
  ml_dsa_details: {
    algorithm: string;
    standard: string;
    security_level: string;
    hard_problem: string;
    public_key_size: number;
    private_key_size: number;
    signature_size: number;
    lattice_dimension: number;
  };
}

export interface SignedComponent {
  component: {
    name: string;
    version: string;
    ecosystem: string;
    purl: string;
    description: string;
    author: string;
    license: string;
    homepage: string;
    sha256: string;
    size_bytes: number;
    upload_date: string;
    dependencies: string[];
    depth: number;
  };
  sha256_signed: string;
  ed25519_signature: string;
  ml_dsa_signature: string;
  public_key_ed25519: string;
  public_key_ml_dsa: string;
  algorithm: string;
  fips_standard: string;
  security_level: string;
  signed_at: string;
  signature_size_bytes: number;
  cves: Array<{
    id: string;
    severity: string;
    summary: string;
    fixed_in?: string;
    published: string;
  }>;
}

export interface SBOM {
  bom_format: string;
  spec_version: string;
  serial_number: string;
  generated_at: string;
  tool: string;
  components: SignedComponent[];
  total_components: number;
  quantum_safe: boolean;
  algorithm: string;
  fips_standard: string;
}

export function generateKeypair(): Promise<KeygenResult> {
  return api.post("/sign/keygen", {});
}

export function signAllComponents(
  components: ResolvedPackage[]
): Promise<SBOM> {
  return api.post("/sign/sign-all", { components });
}
