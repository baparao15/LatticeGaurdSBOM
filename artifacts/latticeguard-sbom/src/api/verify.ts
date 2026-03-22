import { api } from "./client";
import type { SBOM } from "./signing";

export interface VerifyResult {
  component: string;
  version: string;
  hash_match: boolean;
  ed25519_valid: boolean;
  ml_dsa_valid: boolean;
  overall_valid: boolean;
  recomputed_hash?: string;
  stored_hash?: string;
  was_tampered?: boolean;
  error?: string;
}

export interface VerifyReport {
  overall_valid: boolean;
  total: number;
  passed: number;
  failed: number;
  results: VerifyResult[];
  status: string;
}

export interface TamperReport extends VerifyReport {
  tampered_component: string;
  tampered_index: number;
  attack_type: string;
  blocked_by: string;
}

export function verifySBOM(sbom: SBOM): Promise<VerifyReport> {
  return api.post("/verify/verify-sbom", sbom);
}

export function simulateTamper(sbom: SBOM): Promise<TamperReport> {
  return api.post("/verify/tamper-simulate", sbom);
}
