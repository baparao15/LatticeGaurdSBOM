import { api } from "./client";

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
  return api.get<{ status: string; real_oqs: boolean; algorithm: string }>(
    "/health"
  );
}
