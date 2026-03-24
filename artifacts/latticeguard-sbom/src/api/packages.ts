import { api } from "./client";

// ── Core types ─────────────────────────────────────────────────────────────────
export interface CVE {
  id: string;
  severity: string;
  summary: string;
  fixed_in?: string;
  published: string;
}

export interface PackageFile {
  filename: string;
  file_type: "wheel" | "sdist" | "egg" | "installer" | "other";
  size_bytes: number;
  sha256: string;
  url?: string;
  python_version?: string;
  requires_python?: string;
  python_tag?: string;
  abi_tag?: string;
  platform_tag?: string;
  platform_os?: "linux" | "macos" | "windows" | "any" | "other";
  platform_arch?: "x86_64" | "arm64" | "x86" | "any";
}

export interface Component {
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
  file_count: number;
  file_types: string[];
  files: PackageFile[];
  first_release_date?: string;
  release_count?: number;
}

export interface ResolvedPackage {
  component: Component;
  cves: CVE[];
  transitive_count: number;
  transitive: Component[];
}

export interface ResolveError {
  package: string;
  requested_version?: string;
  error: string;
  type: "VERSION_NOT_FOUND" | "FETCH_ERROR";
}

export interface ResolveResult {
  components: ResolvedPackage[];
  errors: ResolveError[];
  total_found: number;
  total_failed: number;
}

export interface ManualResult {
  status: "found" | "error";
  component?: Component;
  cves?: CVE[];
  package?: string;
  message?: string;
  available_versions?: string[];
}

// ── Phase 1: Name Check ────────────────────────────────────────────────────────
export interface NameCheckResult {
  package_name: string;
  normalized_name: string;
  verdict: "VERIFIED" | "LIKELY_TYPOSQUAT" | "SUSPICIOUS" | "UNKNOWN";
  confidence: number;
  nearest_match: string | null;
  edit_distance: number | null;
  list_size: number;
  list_integrity_ok: boolean;
  ml_dsa_signature: string;
  ed25519_signature: string;
  public_key_ml_dsa: string;
  public_key_ed25519: string;
  checked_at: number;
  algorithm: string;
  fips_standard: string;
}

export interface NameCheckBatchResult {
  results: NameCheckResult[];
  total: number;
}

// ── Phase 2: Risk Score ────────────────────────────────────────────────────────
export interface RiskBreakdown {
  cve_score: number;
  age_score: number;
  maintainer_score: number;
  download_score: number;
  name_score: number;
}

export interface RiskScore {
  package_name: string;
  version: string;
  total_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH";
  breakdown: RiskBreakdown;
  monthly_downloads: number | null;
  release_count: number;
  signals: Record<string, unknown>;
  ml_dsa_signature: string;
  ed25519_signature: string;
  public_key_ml_dsa: string;
  public_key_ed25519: string;
  computed_at: number;
  algorithm: string;
  fips_standard: string;
}

export interface RiskBatchResult {
  scores: RiskScore[];
  total_packages: number;
  aggregate_score: number;
  worst_package: RiskScore | null;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
}

// ── Phase 3: Static Scan ───────────────────────────────────────────────────────
export interface StaticFinding {
  pattern: string;
  file: string;
  line_number: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  line_content: string;
}

export interface StaticScanResult {
  package_name: string;
  version: string;
  sdist_url: string;
  findings: StaticFinding[];
  finding_count: number;
  scanned_files: string[];
  error: string | null;
  scanned_at: number;
  ml_dsa_signature: string;
  ed25519_signature: string;
  public_key_ml_dsa: string;
  public_key_ed25519: string;
  algorithm: string;
  fips_standard: string;
}

export interface StaticBatchResult {
  results: StaticScanResult[];
  total_scanned: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
}

// ── Phase 6: License ───────────────────────────────────────────────────────────
export interface LicenseFinding {
  package_name: string;
  version: string;
  license_raw: string;
  spdx_id: string;
  issues: string[];
  is_copyleft: boolean;
  is_agpl: boolean;
  is_ambiguous: boolean;
}

export interface LicenseReport {
  packages: LicenseFinding[];
  total_packages: number;
  has_copyleft: boolean;
  has_agpl: boolean;
  has_ambiguous: boolean;
  compatibility_issues: string[];
  ml_dsa_signature: string;
  ed25519_signature: string;
  public_key_ml_dsa: string;
  public_key_ed25519: string;
  generated_at: number;
  algorithm: string;
  fips_standard: string;
}

// ── Phase 4: Audit Log ─────────────────────────────────────────────────────────
export interface AuditEvent {
  id: string;
  event_type: string;
  description: string;
  details: Record<string, unknown>;
  timestamp: number;
  ml_dsa_signature: string;
  ed25519_signature: string;
  public_key_ml_dsa: string;
  public_key_ed25519: string;
  signature_size_bytes: number;
  algorithm: string;
  fips_standard: string;
  security_level: string;
}

// ── API functions ──────────────────────────────────────────────────────────────
export function resolveDependencies(
  rawText: string,
  ecosystem: string,
  resolveTransitive = true
): Promise<ResolveResult> {
  return api.post("/packages/resolve", {
    raw_text: rawText,
    ecosystem,
    resolve_transitive: resolveTransitive,
  });
}

export function manualLookup(
  packages: Array<{ name: string; version?: string; ecosystem: string }>
): Promise<ManualResult[]> {
  return api.post("/packages/manual", { packages });
}

export function checkHealth() {
  return api.get<{ status: string; real_oqs: boolean; algorithm: string; name_list_size: number }>(
    "/health"
  );
}

// Phase 1
export function checkNamesBatch(names: string[]): Promise<NameCheckBatchResult> {
  return api.post("/namecheck/batch", { names });
}

// Phase 2
export function scoreRiskBatch(packages: Array<{
  package_name: string;
  version: string;
  ecosystem: string;
  cves: CVE[];
  upload_date: string;
  first_release_date?: string;
  release_count: number;
  maintainer?: string;
  name_verdict: string;
}>): Promise<RiskBatchResult> {
  return api.post("/risk/score-batch", { packages });
}

// Phase 3
export function scanSdistBatch(packages: Array<{
  package_name: string;
  version: string;
  sdist_url: string;
}>): Promise<StaticBatchResult> {
  return api.post("/scan/sdist-batch", { packages });
}

// Phase 6
export function analyzeLicenses(packages: Array<{
  name: string;
  version: string;
  license: string;
}>): Promise<LicenseReport> {
  return api.post("/license/analyze", { packages });
}

// Phase 4
export function getAuditEvents(): Promise<{ events: AuditEvent[]; total: number }> {
  return api.get("/audit/events");
}
