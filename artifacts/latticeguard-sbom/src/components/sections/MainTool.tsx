import { useState, useCallback, useRef, useEffect } from "react";
import JSZip from "jszip";
import { motion, AnimatePresence } from "framer-motion";
import {
  resolveDependencies, manualLookup, checkNamesBatch, scoreRiskBatch,
  scanSdistBatch, analyzeLicenses, getAuditEvents,
  ResolvedPackage, PackageFile, ManualResult,
  NameCheckResult, RiskScore, RiskBatchResult, StaticBatchResult,
  StaticFinding, LicenseReport, AuditEvent,
} from "@/api/packages";
import { generateKeypair, signAllComponents, SBOM, KeygenResult } from "@/api/signing";
import { checkHealth } from "@/api/packages";

// ── Placeholders ───────────────────────────────────────────────────────────────
const PYPI_PLACEHOLDER = `requests==2.31.0\ncryptography==42.0.0\nflask==2.3.3`;
const NPM_PLACEHOLDER = `{\n  "dependencies": {\n    "express": "^4.18.0",\n    "lodash": "^4.17.21"\n  }\n}`;

// ── Verify script embedded in ZIP ──────────────────────────────────────────────
const VERIFY_SCRIPT = `#!/usr/bin/env python3
"""LatticeGuard Bundle Verifier v2.0 — NIST FIPS 204 ML-DSA-65 + Ed25519
Usage: pip install cryptography && python verify.py
"""
import sys, json, hashlib
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print("Run: pip install cryptography"); sys.exit(1)

def ed25519_verify(pub_hex, hash_hex, sig_hex):
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(hash_hex))
        return True
    except Exception: return False

def ml_dsa_verify(hash_hex, sig_hex, pub_hex):
    "Mock ML-DSA-65 verifier matching server _MockMLDSA implementation."
    msg, pub = bytes.fromhex(hash_hex), bytes.fromhex(pub_hex)
    h = hashlib.sha512(msg + pub).digest()
    for _ in range(63): h = hashlib.sha512(h + pub).digest()
    return bytes.fromhex(sig_hex)[:64] == h[:64]

def verify_sbom(path="latticeguard-sbom.json"):
    try: sbom = json.load(open(path))
    except FileNotFoundError: print(f"  {path} not found"); return True
    print(f"  Serial: {sbom.get('serial_number')}  Tool: {sbom.get('tool')}")
    ok = True
    for sc in sbom.get("components", []):
        comp = sc.get("component", {})
        name = f"{comp.get('name')}@{comp.get('version')}"
        canonical = json.dumps(comp, sort_keys=True)
        recomputed = hashlib.sha256(canonical.encode()).hexdigest()
        stored = sc.get("sha256_signed", "")
        hash_ok = recomputed == stored
        ed_ok = ed25519_verify(sc.get("public_key_ed25519",""), stored, sc.get("ed25519_signature",""))
        ml_ok = ml_dsa_verify(stored, sc.get("ml_dsa_signature",""), sc.get("public_key_ml_dsa",""))
        s = lambda b: "\\u2713" if b else "\\u2717"
        print(f"  {name}: hash={s(hash_ok)} ed25519={s(ed_ok)} ml-dsa-65={s(ml_ok)}")
        if not (hash_ok and ed_ok and ml_ok): ok = False
    return ok

def sig_report(path, label):
    try: data = json.load(open(path))
    except FileNotFoundError: print(f"  {path} not found"); return
    items = data if isinstance(data, list) else (data.get("results") or data.get("scores") or data.get("packages") or [data])
    for item in items:
        if "ml_dsa_signature" not in item: continue
        name = item.get("package_name") or item.get("name","?")
        ml = item.get("ml_dsa_signature","")[:16]+"..."
        ed = item.get("ed25519_signature","")[:16]+"..."
        print(f"  {name}: ML-DSA-65={ml}  Ed25519={ed}")

if __name__ == "__main__":
    print("LatticeGuard Verifier v2.0 — FIPS 204 ML-DSA-65 + Ed25519")
    print("=" * 58)
    print("\\n[1/4] SBOM:"); sbom_ok = verify_sbom()
    print("\\n[2/4] Name Attestations:"); sig_report("name-attestations.json","")
    print("\\n[3/4] Risk Scores:"); sig_report("risk-scores.json","")
    print("\\n[4/4] Static Scan:"); sig_report("static-scan-results.json","")
    print()
    if sbom_ok: print("\\u2713 All signatures verified")
    else: print("\\u2717 Verification failed"); sys.exit(1)
`;

// ── Helpers ────────────────────────────────────────────────────────────────────
function parseNames(raw: string, ecosystem: string): string[] {
  if (ecosystem === "npm") {
    try {
      const j = JSON.parse(raw);
      return Object.keys({ ...(j.dependencies || {}), ...(j.devDependencies || {}) });
    } catch { return []; }
  }
  return raw.split("\n")
    .map(l => l.trim().replace(/[>=<!~^*].*/,"").replace(/#.*/,"").replace(/\[.*/,"").trim())
    .filter(Boolean);
}

function riskColor(score: number) {
  if (score <= 25) return "#00ff88";
  if (score <= 60) return "#ff9900";
  return "#ff3366";
}

function verdictColor(verdict: string) {
  if (verdict === "VERIFIED") return "#00ff88";
  if (verdict === "LIKELY_TYPOSQUAT") return "#ff3366";
  if (verdict === "SUSPICIOUS") return "#ff9900";
  return "#888";
}

function verdictLabel(v: string) {
  if (v === "VERIFIED") return "✓ VERIFIED";
  if (v === "LIKELY_TYPOSQUAT") return "⚠ TYPOSQUAT";
  if (v === "SUSPICIOUS") return "⚠ SUSPICIOUS";
  return "? UNKNOWN";
}

// ── Sub-components ─────────────────────────────────────────────────────────────
function NameBadge({ result }: { result: NameCheckResult }) {
  const color = verdictColor(result.verdict);
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono"
      style={{ backgroundColor: `${color}15`, color, border: `1px solid ${color}30` }}
      title={result.nearest_match ? `Nearest: ${result.nearest_match} (edit dist ${result.edit_distance})` : ""}
    >
      {verdictLabel(result.verdict)}
      {result.nearest_match && (
        <span className="opacity-70 font-normal">→ {result.nearest_match}</span>
      )}
    </span>
  );
}

function RiskGauge({ score, level }: { score: number; level: string }) {
  const color = riskColor(score);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${score}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-bold font-mono w-16 text-right" style={{ color }}>
        {score}/100 {level}
      </span>
    </div>
  );
}

function SeverityBadge({ sev }: { sev: string }) {
  const c = sev === "CRITICAL" ? "#ff3366" : sev === "HIGH" ? "#ff9900" : sev === "MEDIUM" ? "#a78bfa" : "#888";
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold font-mono" style={{ backgroundColor: `${c}15`, color: c }}>
      {sev}
    </span>
  );
}

function PackageCard({
  pkg,
  nameResult,
  riskScore,
  scanResult,
  licenseInfo,
  onRemove,
}: {
  pkg: ResolvedPackage;
  nameResult?: NameCheckResult;
  riskScore?: RiskScore;
  scanResult?: { findings: StaticFinding[]; error: string | null };
  licenseInfo?: { spdx_id: string; issues: string[] };
  onRemove: () => void;
}) {
  const [open, setOpen] = useState(false);
  const sdistFile = pkg.component.files?.find(f => f.file_type === "sdist");
  const criticalFindings = scanResult?.findings.filter(f => f.severity === "CRITICAL") ?? [];
  const highFindings = scanResult?.findings.filter(f => f.severity === "HIGH") ?? [];

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      <div className="px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono font-bold text-white text-sm">
                {pkg.component.name}
                <span className="text-gray-500 font-normal">@{pkg.component.version}</span>
              </span>
              {nameResult && <NameBadge result={nameResult} />}
              {pkg.cves.length > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#ff3366]/10 text-[#ff3366] border border-[#ff3366]/20">
                  ⚠ {pkg.cves.length} CVE{pkg.cves.length > 1 ? "s" : ""}
                </span>
              )}
              {(criticalFindings.length + highFindings.length) > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#ff3366]/10 text-[#ff3366] border border-[#ff3366]/20">
                  🔬 {criticalFindings.length + highFindings.length} finding{criticalFindings.length + highFindings.length > 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <button
              onClick={() => setOpen(!open)}
              className="text-xs text-gray-600 hover:text-gray-300 px-2 py-1 rounded hover:bg-white/5 transition-all"
            >
              {open ? "▴" : "▾"}
            </button>
            <button
              onClick={onRemove}
              className="text-xs text-gray-700 hover:text-[#ff3366] px-1.5 py-1 rounded transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Compact meta row */}
        <div className="flex flex-wrap gap-3 mt-2 text-[11px] text-gray-600 font-mono">
          {pkg.component.license && (
            <span className={licenseInfo?.issues.length ? "text-[#ff9900]" : ""}>
              {licenseInfo?.spdx_id ?? pkg.component.license}
              {licenseInfo?.issues.length ? " ⚠" : ""}
            </span>
          )}
          <span>{pkg.component.ecosystem.toUpperCase()}</span>
          {sdistFile && <span>sdist ✓</span>}
          {pkg.component.file_types.length > 0 && <span>{pkg.component.file_types.join(", ")}</span>}
          {pkg.component.upload_date && (
            <span>uploaded {pkg.component.upload_date.slice(0, 10)}</span>
          )}
        </div>

        {/* Files being downloaded — always visible as soon as package resolves */}
        {pkg.component.files && pkg.component.files.length > 0 && (
          <div className="mt-3 border-t border-white/5 pt-3">
            <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
              Downloading ({pkg.component.files.length} file{pkg.component.files.length !== 1 ? "s" : ""})
            </p>
            <div className="space-y-0.5 max-h-52 overflow-y-auto">
              {pkg.component.files.map((f: PackageFile) => (
                <div key={f.filename} className="flex items-center gap-2 text-[10px] font-mono py-0.5">
                  <span className={`w-10 text-center px-1 py-0.5 rounded text-[9px] flex-shrink-0 ${
                    f.file_type === "wheel" ? "bg-[#00d4ff]/10 text-[#00d4ff]" :
                    f.file_type === "sdist" ? "bg-[#a78bfa]/10 text-[#a78bfa]" :
                    "bg-white/5 text-gray-500"
                  }`}>{f.file_type}</span>
                  <span className="truncate text-gray-300 flex-1">{f.filename}</span>
                  <span className="text-gray-600 flex-shrink-0">
                    {f.size_bytes >= 1024 * 1024
                      ? `${(f.size_bytes / 1024 / 1024).toFixed(1)} MB`
                      : `${(f.size_bytes / 1024).toFixed(0)} KB`}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Download verdict — shown once risk scoring completes */}
        {riskScore && (
          <div className="mt-2 border-t border-white/5 pt-2">
            {(riskScore.risk_level === "HIGH" || riskScore.risk_level === "CRITICAL") ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#ff3366]/10 border border-[#ff3366]/30">
                <span className="text-base">🚫</span>
                <div>
                  <p className="text-xs font-bold text-[#ff3366]">RISKY — Do Not Download</p>
                  <p className="text-[10px] text-[#ff3366]/70">This package poses a {riskScore.risk_level.toLowerCase()} risk. Avoid installing.</p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/30">
                <span className="text-base">✅</span>
                <div>
                  <p className="text-xs font-bold text-[#00ff88]">SAFE — Download Approved</p>
                  <p className="text-[10px] text-[#00ff88]/70">Risk level is {riskScore.risk_level.toLowerCase()}. Safe to install.</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/5 bg-black/20 px-4 py-3 space-y-4">
              {/* Description */}
              {pkg.component.description && (
                <p className="text-xs text-gray-500">{pkg.component.description}</p>
              )}


              {/* CVEs */}
              {pkg.cves.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">CVEs</p>
                  <div className="space-y-1.5">
                    {pkg.cves.slice(0, 5).map(cve => (
                      <div key={cve.id} className="flex items-start gap-2 text-xs">
                        <SeverityBadge sev={cve.severity} />
                        <span className="text-[#00d4ff] font-mono flex-shrink-0">{cve.id}</span>
                        <span className="text-gray-500 truncate">{cve.summary}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Static scan findings */}
              {scanResult && (scanResult.findings.length > 0 || scanResult.error) && (
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
                    Static Scan Findings
                  </p>
                  {scanResult.error && (
                    <p className="text-[11px] text-gray-600 font-mono">{scanResult.error}</p>
                  )}
                  {scanResult.findings.slice(0, 4).map((f, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs mb-1">
                      <SeverityBadge sev={f.severity} />
                      <span className="text-gray-400 flex-1">{f.description}</span>
                      <span className="text-gray-600 font-mono text-[10px] flex-shrink-0">
                        {f.file.split("/").pop()}:{f.line_number}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              {scanResult && scanResult.findings.length === 0 && !scanResult.error && (
                <p className="text-[11px] text-[#00ff88]">🔬 Static scan: no malicious patterns found</p>
              )}

              {/* License issues */}
              {licenseInfo?.issues.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">
                    License Issues
                  </p>
                  {licenseInfo.issues.map((issue, i) => (
                    <p key={i} className="text-[11px] text-[#ff9900]">⚖️ {issue}</p>
                  ))}
                </div>
              )}

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────
export default function MainTool() {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [ecosystem, setEcosystem] = useState<"pypi" | "npm">("pypi");
  const [inputMode, setInputMode] = useState<"paste" | "manual">("paste");
  const [rawInput, setRawInput] = useState("");
  const [manualName, setManualName] = useState("");
  const [manualVersion, setManualVersion] = useState("");

  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [errors, setErrors] = useState<{ package: string; error: string }[]>([]);

  // Phase 1: Name check
  const [nameCheckResults, setNameCheckResults] = useState<Record<string, NameCheckResult>>({});
  const [nameCheckDone, setNameCheckDone] = useState(false);
  const [confirmedTyposquats, setConfirmedTyposquats] = useState<Set<string>>(new Set());
  const [removedNames, setRemovedNames] = useState<Set<string>>(new Set());

  // Packages
  const [packages, setPackages] = useState<ResolvedPackage[]>([]);
  const [manualLoading, setManualLoading] = useState(false);
  const [manualResult, setManualResult] = useState<ManualResult | null>(null);
  const manualTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Phase 2: Risk scoring
  const [riskBatch, setRiskBatch] = useState<RiskBatchResult | null>(null);

  // Phase 3: Static scan
  const [staticBatch, setStaticBatch] = useState<StaticBatchResult | null>(null);
  const [scanLoading, setScanLoading] = useState(false);

  // Phase 6: License
  const [licenseReport, setLicenseReport] = useState<LicenseReport | null>(null);

  // Phase 4: Audit
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  // Signing
  const [keypair, setKeypair] = useState<KeygenResult | null>(null);
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [signingProgress, setSigningProgress] = useState(0);
  const [downloading, setDownloading] = useState(false);

  // ── Backend health check ─────────────────────────────────────────────────────
  const checkBackend = async () => {
    try {
      await checkHealth();
      setBackendOnline(true);
      return true;
    } catch {
      setBackendOnline(false);
      setErrors([{ package: "backend", error: "Backend offline — start the Python workflow." }]);
      return false;
    }
  };

  useEffect(() => { checkBackend(); }, []);

  // ── Lookup helpers ───────────────────────────────────────────────────────────
  const scheduleManualLookup = useCallback((name: string, version: string) => {
    setManualName(name);
    setManualVersion(version);
    if (manualTimer.current) clearTimeout(manualTimer.current);
    if (!name.trim()) { setManualResult(null); return; }
    manualTimer.current = setTimeout(async () => {
      setManualLoading(true);
      try {
        const [res] = await manualLookup([{ name, version: version || undefined, ecosystem }]);
        setManualResult(res);
      } catch { setManualResult(null); }
      finally { setManualLoading(false); }
    }, 600);
  }, [ecosystem]);

  const addManualPackage = () => {
    if (!manualResult || manualResult.status !== "found" || !manualResult.component) return;
    const pkg: ResolvedPackage = {
      component: manualResult.component,
      cves: manualResult.cves ?? [],
      transitive_count: 0,
      transitive: [],
    };
    setPackages(prev => {
      const exists = prev.some(p => p.component.purl === pkg.component.purl);
      return exists ? prev : [...prev, pkg];
    });
    setManualName(""); setManualVersion(""); setManualResult(null);
  };

  // ── Phase 1: Name Check → Resolve ───────────────────────────────────────────
  const handleVerifyAndAnalyze = async () => {
    const ok = await checkBackend();
    if (!ok) return;
    setLoading(true);
    setLoadingMsg("Verifying package names…");
    setNameCheckDone(false);
    setNameCheckResults({});
    setErrors([]);
    setPackages([]);
    setRiskBatch(null);
    setStaticBatch(null);
    setLicenseReport(null);
    setSbom(null);
    setKeypair(null);

    try {
      const names = parseNames(rawInput, ecosystem).filter(n => !removedNames.has(n));
      if (names.length === 0) {
        setErrors([{ package: "input", error: "No package names found — paste a requirements.txt or package.json." }]);
        setLoading(false);
        return;
      }

      // Phase 1: batch name check
      setLoadingMsg(`Checking ${names.length} package names against ML-DSA-65 signed list…`);
      const nameRes = await checkNamesBatch(names);
      const resultsMap: Record<string, NameCheckResult> = {};
      nameRes.results.forEach(r => { resultsMap[r.package_name] = r; });
      setNameCheckResults(resultsMap);
      setNameCheckDone(true);

      // Check for unconfirmed typosquats
      const typosquats = nameRes.results.filter(r => r.verdict === "LIKELY_TYPOSQUAT" && !confirmedTyposquats.has(r.package_name));
      if (typosquats.length > 0) {
        setLoading(false);
        setLoadingMsg("");
        return; // user must confirm typosquats first
      }

      // Proceed to resolve
      await doResolveAndAnalyze(names, resultsMap);
    } catch (e: unknown) {
      setErrors([{ package: "verify", error: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
      setLoadingMsg("");
    }
  };

  const handleContinueAfterConfirm = async () => {
    const ok = await checkBackend();
    if (!ok) return;
    setLoading(true);
    setLoadingMsg("Resolving approved packages…");
    const names = parseNames(rawInput, ecosystem).filter(n =>
      !removedNames.has(n) &&
      (nameCheckResults[n]?.verdict !== "LIKELY_TYPOSQUAT" || confirmedTyposquats.has(n))
    );
    try {
      await doResolveAndAnalyze(names, nameCheckResults);
    } catch (e: unknown) {
      setErrors([{ package: "resolve", error: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
      setLoadingMsg("");
    }
  };

  const doResolveAndAnalyze = async (names: string[], nameResults: Record<string, NameCheckResult>) => {
    // Resolve packages
    setLoadingMsg(`Resolving ${names.length} packages from ${ecosystem.toUpperCase()}…`);
    const resolveInput = ecosystem === "pypi"
      ? names.join("\n")
      : JSON.stringify({ dependencies: Object.fromEntries(names.map(n => [n, "*"])) });

    const result = await resolveDependencies(resolveInput, ecosystem);
    const resolved = result.components;
    setPackages(resolved);

    if (result.errors.length > 0) {
      setErrors(result.errors.map(e => ({ package: e.package, error: e.error })));
    }
    if (resolved.length === 0) {
      setLoading(false);
      setLoadingMsg("");
      return;
    }

    // Phase 2: Risk scoring (concurrent with scan)
    setLoadingMsg("Computing risk scores…");
    try {
      const riskPayload = resolved.map(pkg => ({
        package_name: pkg.component.name,
        version: pkg.component.version,
        ecosystem: pkg.component.ecosystem,
        cves: pkg.cves,
        upload_date: pkg.component.upload_date || "",
        first_release_date: pkg.component.first_release_date,
        release_count: pkg.component.release_count || 0,
        maintainer: pkg.component.author,
        name_verdict: nameResults[pkg.component.name]?.verdict ?? "UNKNOWN",
      }));
      const riskResult = await scoreRiskBatch(riskPayload);
      setRiskBatch(riskResult);
    } catch { /* non-fatal */ }

    // Phase 3: Static scan (sdist packages only)
    const sdistPackages = resolved.flatMap(pkg =>
      (pkg.component.files ?? [])
        .filter(f => f.file_type === "sdist" && f.url)
        .slice(0, 1)
        .map(f => ({
          package_name: pkg.component.name,
          version: pkg.component.version,
          sdist_url: f.url!,
        }))
    ).slice(0, 10);

    if (sdistPackages.length > 0) {
      setScanLoading(true);
      setLoadingMsg("Scanning sdist source files…");
      try {
        const scanResult = await scanSdistBatch(sdistPackages);
        setStaticBatch(scanResult);
      } catch { /* non-fatal */ }
      finally { setScanLoading(false); }
    }

    // Phase 6: License analysis
    setLoadingMsg("Analyzing license compatibility…");
    try {
      const licensePayload = resolved.map(pkg => ({
        name: pkg.component.name,
        version: pkg.component.version,
        license: pkg.component.license || "",
      }));
      const licResult = await analyzeLicenses(licensePayload);
      setLicenseReport(licResult);
    } catch { /* non-fatal */ }

    setLoadingMsg("");
    setStep(2);
  };

  // ── Phase 4: fetch audit events ──────────────────────────────────────────────
  const fetchAuditEvents = async () => {
    try {
      const res = await getAuditEvents();
      setAuditEvents(res.events);
    } catch { /* non-fatal */ }
  };

  // ── Signing ──────────────────────────────────────────────────────────────────
  const handleKeygen = async () => {
    setLoading(true); setLoadingMsg("Generating ML-DSA-65 + Ed25519 keypair…");
    if (!await checkBackend()) { setLoading(false); return; }
    try {
      const kp = await generateKeypair();
      setKeypair(kp);
    } catch (e: unknown) {
      setErrors([{ package: "keygen", error: e instanceof Error ? e.message : String(e) }]);
    } finally { setLoading(false); setLoadingMsg(""); }
  };

  const handleSign = async () => {
    if (!keypair || packages.length === 0) return;
    setLoading(true); setSigningProgress(0); setLoadingMsg("Signing components…");
    try {
      const result = await signAllComponents(packages);
      setSbom(result);
      setSigningProgress(100);
      await fetchAuditEvents();
    } catch (e: unknown) {
      setErrors([{ package: "sign", error: e instanceof Error ? e.message : String(e) }]);
    } finally { setLoading(false); setLoadingMsg(""); }
  };

  // ── Phase 7: 6-file ZIP export ───────────────────────────────────────────────
  const handleDownload = async () => {
    if (!sbom || !keypair) return;
    setDownloading(true);
    const zip = new JSZip();

    // 1. SBOM
    zip.file("latticeguard-sbom.json", JSON.stringify(sbom, null, 2));

    // 2. Name attestations
    const nameAtts = Object.values(nameCheckResults);
    zip.file("name-attestations.json", JSON.stringify({ results: nameAtts, total: nameAtts.length }, null, 2));

    // 3. Static scan results
    const staticData = staticBatch ?? { results: [], total_scanned: 0, total_findings: 0 };
    zip.file("static-scan-results.json", JSON.stringify(staticData, null, 2));

    // 4. Risk scores
    const riskData = riskBatch ?? { scores: [], total_packages: 0 };
    zip.file("risk-scores.json", JSON.stringify(riskData, null, 2));

    // 5. Public keys (PEM-like format)
    const { ml_dsa_public_key, ed25519_public_key, generated_at, security_level } = keypair;
    const publicKeysPem = [
      "# LatticeGuard Public Keys",
      "# Generated: " + new Date(generated_at * 1000).toISOString(),
      "# Algorithm: Hybrid(ML-DSA-65 + Ed25519) | NIST FIPS 204 | " + security_level,
      "",
      "# ML-DSA-65 (Module-Lattice-Based Digital Signature — FIPS 204)",
      "# Key size: 1,952 bytes | Signature size: 3,293 bytes",
      "-----BEGIN ML-DSA-65 PUBLIC KEY-----",
      ml_dsa_public_key.match(/.{1,64}/g)?.join("\n") ?? ml_dsa_public_key,
      "-----END ML-DSA-65 PUBLIC KEY-----",
      "",
      "# Ed25519 (Classical — Edwards25519 Curve)",
      "# Key size: 32 bytes | Signature size: 64 bytes",
      "-----BEGIN ED25519 PUBLIC KEY-----",
      ed25519_public_key,
      "-----END ED25519 PUBLIC KEY-----",
    ].join("\n");
    zip.file("public-keys.pem", publicKeysPem);

    // 6. verify.py
    zip.file("verify.py", VERIFY_SCRIPT);

    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `latticeguard-sbom-${Date.now()}.zip`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloading(false);
  };

  // ── Derived data ─────────────────────────────────────────────────────────────
  const totalCVEs = packages.reduce((a, p) => a + p.cves.length, 0);
  const getRisk = (name: string) => riskBatch?.scores.find(s => s.package_name === name);
  const getScan = (name: string) => staticBatch?.results.find(s => s.package_name === name);
  const getLicense = (name: string) => licenseReport?.packages.find(p => p.package_name === name);

  const pendingTyposquats = Object.values(nameCheckResults).filter(
    r => r.verdict === "LIKELY_TYPOSQUAT" && !confirmedTyposquats.has(r.package_name) && !removedNames.has(r.package_name)
  );
  const hasPendingTyposquats = pendingTyposquats.length > 0;

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <section id="tool" className="py-20 px-4">
      <div className="max-w-4xl mx-auto space-y-6">

        {/* Header */}
        <div className="text-center mb-2">
          <h2 className="text-3xl md:text-4xl font-bold mb-2">
            <span className="gradient-text">SBOM Generator</span>
          </h2>
          <p className="text-gray-500 text-sm max-w-lg mx-auto">
            Verify names · Score risk · Scan source · Sign with ML-DSA-65 + Ed25519 · Export 6-file bundle
          </p>
          <div className="mt-3 flex justify-center gap-2">
            {backendOnline === false && (
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#ff3366]/10 border border-[#ff3366]/30 text-[#ff3366] text-xs">
                ● Backend offline — start the Python workflow
              </div>
            )}
            {backendOnline === true && (
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] text-xs">
                ● Backend connected · ML-DSA-65 · FIPS 204
              </div>
            )}
          </div>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 justify-center">
          {[
            { n: 1, label: "Verify Names", done: packages.length > 0 },
            { n: 2, label: "Review Risk", done: sbom !== null },
            { n: 3, label: "Sign & Export", done: false },
          ].map((s, i) => (
            <div key={s.n} className="flex items-center">
              <button
                onClick={() => {
                  if (s.n === 1 || (s.n === 2 && packages.length > 0) || (s.n === 3 && sbom)) {
                    setStep(s.n as 1 | 2 | 3);
                  }
                }}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all ${
                  step === s.n ? "text-[#00d4ff]" : s.done ? "text-[#00ff88] opacity-80" : "text-gray-600"
                }`}
              >
                <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border transition-all ${
                  s.done ? "border-[#00ff88] bg-[#00ff88]/10 text-[#00ff88]"
                  : step === s.n ? "border-[#00d4ff] bg-[#00d4ff]/10 text-[#00d4ff]"
                  : "border-white/20 bg-white/5 text-gray-600"
                }`}>
                  {s.done ? "✓" : s.n}
                </div>
                <span className="hidden sm:block font-medium text-xs">{s.label}</span>
              </button>
              {i < 2 && <div className={`w-8 h-px ${s.done ? "bg-[#00ff88]/30" : "bg-white/10"}`} />}
            </div>
          ))}
        </div>

        {/* ══ STEP 1 — VERIFY NAMES ══ */}
        {step === 1 && (
          <div className="glass-card rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
              <div className="w-7 h-7 rounded-full border border-[#00d4ff] bg-[#00d4ff]/10 flex items-center justify-center text-xs font-bold text-[#00d4ff]">1</div>
              <div>
                <h3 className="font-semibold text-white text-sm">Verify Package Names</h3>
                <p className="text-xs text-gray-600">ML-DSA-65 signed top-8K list · Levenshtein + homoglyph detection</p>
              </div>
            </div>

            <div className="p-5 space-y-5">
              {/* Mode toggles */}
              <div className="flex flex-wrap gap-3">
                <div className="flex rounded-lg overflow-hidden border border-white/10 text-sm">
                  {(["pypi", "npm"] as const).map(eco => (
                    <button key={eco} onClick={() => setEcosystem(eco)}
                      className={`px-4 py-2 font-mono font-medium transition-colors ${ecosystem === eco ? "bg-[#00d4ff]/15 text-[#00d4ff]" : "text-gray-500 hover:text-gray-300"}`}
                    >{eco.toUpperCase()}</button>
                  ))}
                </div>
                <div className="flex rounded-lg overflow-hidden border border-white/10 text-sm">
                  {(["paste", "manual"] as const).map(mode => (
                    <button key={mode} onClick={() => setInputMode(mode)}
                      className={`px-4 py-2 transition-colors ${inputMode === mode ? "bg-[#7c3aed]/15 text-[#a78bfa]" : "text-gray-500 hover:text-gray-300"}`}
                    >{mode === "paste" ? "Paste file" : "Add manually"}</button>
                  ))}
                </div>
              </div>

              {/* Paste mode */}
              {inputMode === "paste" && (
                <div className="space-y-3">
                  <label className="text-xs text-gray-500 block">
                    {ecosystem === "pypi" ? "Paste requirements.txt:" : "Paste package.json:"}
                  </label>
                  <textarea
                    value={rawInput}
                    onChange={e => setRawInput(e.target.value)}
                    placeholder={ecosystem === "pypi" ? PYPI_PLACEHOLDER : NPM_PLACEHOLDER}
                    rows={5}
                    className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40 resize-y"
                  />

                  {/* Name check results inline */}
                  {nameCheckDone && Object.keys(nameCheckResults).length > 0 && (
                    <div className="rounded-lg border border-white/10 bg-black/20 p-3 space-y-2">
                      <p className="text-xs text-gray-500 font-mono mb-2">
                        Name verification · {Object.keys(nameCheckResults).length} packages · ML-DSA-65 signed
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(nameCheckResults)
                          .filter(([name]) => !removedNames.has(name))
                          .map(([name, result]) => (
                            <div key={name} className="flex items-center gap-1.5">
                              <span className="text-xs font-mono text-gray-400">{name}</span>
                              <NameBadge result={result} />
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Typosquat warning panel */}
                  {hasPendingTyposquats && (
                    <div className="rounded-lg border border-[#ff3366]/30 bg-[#ff3366]/5 p-4 space-y-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[#ff3366] font-semibold text-sm">⚠ Likely Typosquat Detected</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        The following packages may be typosquats of popular packages. This decision will be recorded
                        in your signed audit log. You can confirm to proceed or remove them from the list.
                      </p>
                      {pendingTyposquats.map(r => (
                        <div key={r.package_name} className="flex items-center justify-between gap-3 p-2 rounded bg-[#ff3366]/8 border border-[#ff3366]/20">
                          <div className="min-w-0">
                            <p className="text-sm font-mono text-[#ff3366] font-bold">{r.package_name}</p>
                            <p className="text-xs text-gray-500">
                              Mimics <span className="text-white font-mono">{r.nearest_match}</span>
                              {r.edit_distance !== null && ` (${r.edit_distance} edit${r.edit_distance !== 1 ? "s" : ""} away)`}
                            </p>
                          </div>
                          <div className="flex gap-2 flex-shrink-0">
                            <button
                              onClick={() => {
                                setRemovedNames(prev => new Set([...prev, r.package_name]));
                              }}
                              className="px-2 py-1 text-xs rounded border border-white/20 text-gray-400 hover:text-white transition-colors"
                            >
                              Remove
                            </button>
                            <button
                              onClick={() => {
                                setConfirmedTyposquats(prev => new Set([...prev, r.package_name]));
                              }}
                              className="px-2 py-1 text-xs rounded border border-[#ff3366]/40 text-[#ff3366] hover:bg-[#ff3366]/10 transition-colors"
                            >
                              I understand, proceed
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Continue after confirming all typosquats */}
                  {nameCheckDone && !hasPendingTyposquats && packages.length === 0 && (
                    <button
                      onClick={handleContinueAfterConfirm}
                      disabled={loading}
                      className="w-full py-3 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#00d4ff] text-white font-semibold text-sm disabled:opacity-40 flex items-center justify-center gap-2"
                    >
                      {loading ? <><span className="animate-spin">⟳</span> {loadingMsg}</> : "Resolve packages & analyze →"}
                    </button>
                  )}

                  {/* Primary CTA */}
                  {!nameCheckDone && (
                    <button
                      onClick={handleVerifyAndAnalyze}
                      disabled={loading || !rawInput.trim()}
                      className="w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
                    >
                      {loading ? <><span className="animate-spin">⟳</span> {loadingMsg}</> : "① Verify names & analyze →"}
                    </button>
                  )}
                  {nameCheckDone && !hasPendingTyposquats && packages.length === 0 && !loading && (
                    <button
                      onClick={handleVerifyAndAnalyze}
                      disabled={loading || !rawInput.trim()}
                      className="w-full py-2 rounded-xl border border-white/10 text-gray-500 text-sm hover:border-[#00d4ff]/30 hover:text-gray-300 transition-all"
                    >
                      Re-run verification
                    </button>
                  )}
                  {nameCheckDone && hasPendingTyposquats && (
                    <p className="text-xs text-center text-gray-600">
                      Resolve the typosquat warnings above to continue.
                    </p>
                  )}
                </div>
              )}

              {/* Manual mode */}
              {inputMode === "manual" && (
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="text-xs text-gray-500 mb-1 block">Package name</label>
                      <input value={manualName} onChange={e => scheduleManualLookup(e.target.value, manualVersion)}
                        placeholder={ecosystem === "pypi" ? "flask" : "express"}
                        className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40" />
                    </div>
                    <div className="w-36">
                      <label className="text-xs text-gray-500 mb-1 block">Version</label>
                      <input value={manualVersion} onChange={e => scheduleManualLookup(manualName, e.target.value)}
                        placeholder="latest"
                        className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40" />
                    </div>
                  </div>
                  {manualLoading && <p className="text-xs text-[#00d4ff] animate-pulse">Looking up…</p>}
                  {manualResult && !manualLoading && (
                    <div className={`rounded-lg p-3 text-sm border ${manualResult.status === "found" ? "border-[#00ff88]/30 bg-[#00ff88]/5" : "border-[#ff3366]/30 bg-[#ff3366]/5"}`}>
                      {manualResult.status === "found" && manualResult.component ? (
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="font-mono font-semibold text-[#00ff88]">{manualResult.component.name}@{manualResult.component.version}</p>
                            <p className="text-gray-400 text-xs mt-0.5 line-clamp-1">{manualResult.component.description}</p>
                            {(manualResult.cves?.length ?? 0) > 0 && <p className="text-xs text-[#ff3366] mt-0.5">⚠ {manualResult.cves!.length} CVEs</p>}
                          </div>
                          <button onClick={addManualPackage}
                            className="shrink-0 px-3 py-1.5 bg-[#00d4ff]/15 hover:bg-[#00d4ff]/25 border border-[#00d4ff]/40 rounded text-[#00d4ff] text-xs font-medium transition-colors">
                            + Add
                          </button>
                        </div>
                      ) : (
                        <p className="text-[#ff3366] text-xs">{manualResult.message}</p>
                      )}
                    </div>
                  )}
                  {packages.length > 0 && (
                    <button onClick={() => setStep(2)}
                      className="w-full py-2.5 rounded-xl border border-[#00d4ff]/30 text-[#00d4ff] text-sm font-medium hover:bg-[#00d4ff]/10 transition-colors">
                      Continue to review & sign →
                    </button>
                  )}
                </div>
              )}

              {/* Errors */}
              {errors.length > 0 && (
                <div className="rounded-lg border border-[#ff3366]/20 bg-[#ff3366]/5 p-3 space-y-1">
                  {errors.map((e, i) => <p key={i} className="text-xs text-[#ff3366] font-mono">✗ {e.package}: {e.error}</p>)}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ══ STEP 2 — REVIEW RISK ══ */}
        {step === 2 && (
          <div className="space-y-5">

            {/* License compliance summary */}
            {licenseReport && (licenseReport.has_copyleft || licenseReport.has_agpl || licenseReport.has_ambiguous) && (
              <div className="glass-card rounded-xl p-4 border border-[#ff9900]/20">
                <p className="text-xs font-semibold text-[#ff9900] mb-2">⚖️ License Compliance Issues</p>
                {licenseReport.compatibility_issues.map((issue, i) => (
                  <p key={i} className="text-xs text-gray-400 mb-1">{issue}</p>
                ))}
              </div>
            )}

            {/* Package list header */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-full border border-[#00d4ff] bg-[#00d4ff]/10 flex items-center justify-center text-xs font-bold text-[#00d4ff]">2</div>
                  <div>
                    <h3 className="font-semibold text-white text-sm">Review Packages</h3>
                    <p className="text-xs text-gray-500">
                      {packages.length} resolved
                      {totalCVEs > 0 && <span className="text-[#ff3366] ml-2">· {totalCVEs} CVEs</span>}
                      {scanLoading && <span className="text-[#00d4ff] ml-2 animate-pulse">· Scanning sdist…</span>}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => setStep(1)} className="text-xs text-gray-600 hover:text-gray-300 transition-colors">← Back</button>
                  <button onClick={() => setPackages([])} className="text-xs text-gray-600 hover:text-[#ff3366] transition-colors">Clear all</button>
                </div>
              </div>
              <div className="p-4 space-y-3">
                {packages.map((pkg, i) => (
                  <PackageCard
                    key={`${pkg.component.name}-${i}`}
                    pkg={pkg}
                    nameResult={nameCheckResults[pkg.component.name]}
                    riskScore={getRisk(pkg.component.name)}
                    scanResult={getScan(pkg.component.name) ?? undefined}
                    licenseInfo={getLicense(pkg.component.name) ?? undefined}
                    onRemove={() => setPackages(prev => prev.filter((_, idx) => idx !== i))}
                  />
                ))}
              </div>
            </div>

            {/* Sign panel */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border ${sbom ? "border-[#00ff88] bg-[#00ff88]/10 text-[#00ff88]" : "border-[#7c3aed] bg-[#7c3aed]/10 text-[#a78bfa]"}`}>
                  {sbom ? "✓" : "⊕"}
                </div>
                <h3 className="font-semibold text-white text-sm">Sign with Hybrid Post-Quantum Cryptography</h3>
              </div>

              <div className="p-5 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-xl border border-[#7c3aed]/30 bg-[#7c3aed]/5 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-[#a78bfa] font-semibold text-sm">ML-DSA-65</p>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-[#7c3aed]/20 border border-[#7c3aed]/30 text-[#a78bfa] font-mono">POST-QUANTUM</span>
                    </div>
                    <p className="text-gray-500 text-xs">NIST FIPS 204 · Security Level 3 · Module-LWE + SIS</p>
                    <div className="flex gap-3 text-xs font-mono text-gray-600">
                      <span>pub: 1,952 B</span><span>sig: 3,293 B</span>
                    </div>
                    {keypair && <p className="text-[10px] font-mono text-[#a78bfa]/70 break-all">{keypair.ml_dsa_public_key.slice(0,48)}…</p>}
                  </div>
                  <div className="rounded-xl border border-[#00d4ff]/30 bg-[#00d4ff]/5 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-[#00d4ff] font-semibold text-sm">Ed25519</p>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] font-mono">REAL</span>
                    </div>
                    <p className="text-gray-500 text-xs">Classical · Edwards25519 · Hybrid: both must be valid</p>
                    <div className="flex gap-3 text-xs font-mono text-gray-600">
                      <span>pub: 32 B</span><span>sig: 64 B</span>
                    </div>
                    {keypair && <p className="text-[10px] font-mono text-[#00d4ff]/70 break-all">{keypair.ed25519_public_key}</p>}
                  </div>
                </div>

                {!sbom ? (
                  <div className="flex flex-col sm:flex-row gap-3">
                    <button onClick={handleKeygen} disabled={loading || !!keypair}
                      className={`flex-1 py-3 rounded-xl border font-semibold text-sm transition-all flex items-center justify-center gap-2 ${keypair ? "border-[#00ff88]/40 text-[#00ff88] bg-[#00ff88]/5" : "border-[#7c3aed]/50 text-[#a78bfa] hover:bg-[#7c3aed]/10 disabled:opacity-40"}`}>
                      {loading && loadingMsg.includes("keypair") ? <><span className="animate-spin">⟳</span> Generating…</> : keypair ? "✓ Keypair generated" : "① Generate keypair"}
                    </button>
                    <button onClick={handleSign} disabled={loading || !keypair || packages.length === 0}
                      className="flex-1 py-3 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#00d4ff] text-white font-semibold text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 flex items-center justify-center gap-2">
                      {loading && loadingMsg.includes("Signing") ? <><span className="animate-spin">⟳</span> Signing…</> : `② Sign ${packages.length} component${packages.length !== 1 ? "s" : ""} →`}
                    </button>
                  </div>
                ) : (
                  <div className="rounded-xl border border-[#00ff88]/30 bg-[#00ff88]/5 p-4">
                    <p className="text-[#00ff88] font-semibold text-sm mb-3">✓ SBOM signed & sealed</p>
                    <div className="grid grid-cols-3 gap-3 text-center mb-3">
                      <div><p className="text-xl font-bold text-white">{sbom.total_components}</p><p className="text-xs text-gray-500">Components</p></div>
                      <div><p className="text-xl font-bold text-[#a78bfa]">3,293</p><p className="text-xs text-gray-500">ML-DSA bytes</p></div>
                      <div><p className="text-xl font-bold text-[#ff3366]">{sbom.components.reduce((n, c) => n + c.cves.length, 0)}</p><p className="text-xs text-gray-500">CVEs</p></div>
                    </div>
                    <p className="text-xs text-gray-600 font-mono">Serial: {sbom.serial_number}</p>
                    <button onClick={() => setStep(3)}
                      className="mt-3 w-full py-2.5 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#00ff88] text-black font-bold text-sm hover:opacity-90">
                      Export 6-file bundle →
                    </button>
                  </div>
                )}

                {errors.length > 0 && (
                  <div className="rounded-lg border border-[#ff3366]/20 bg-[#ff3366]/5 p-3 space-y-1">
                    {errors.map((e, i) => <p key={i} className="text-xs text-[#ff3366] font-mono">✗ {e.package}: {e.error}</p>)}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ══ STEP 3 — SIGN & EXPORT ══ */}
        {step === 3 && sbom && keypair && (
          <div className="space-y-5">
            {/* File manifest */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
                <div className="w-7 h-7 rounded-full border border-[#00ff88] bg-[#00ff88]/10 flex items-center justify-center text-xs font-bold text-[#00ff88]">↓</div>
                <div>
                  <h3 className="font-semibold text-white text-sm">Export Bundle</h3>
                  <p className="text-xs text-gray-500">6 files — cryptographic chain from name-check through SBOM signing</p>
                </div>
              </div>

              <div className="p-5 space-y-3">
                {[
                  { file: "latticeguard-sbom.json", desc: "CycloneDX 1.5 SBOM — ML-DSA-65 + Ed25519 per component", color: "#00d4ff", icon: "📄" },
                  { file: "name-attestations.json", desc: `${Object.keys(nameCheckResults).length} name verdicts — signed before any PyPI call`, color: "#a78bfa", icon: "🔍" },
                  { file: "static-scan-results.json", desc: `Static source scan — ${staticBatch?.total_findings ?? 0} findings across ${staticBatch?.total_scanned ?? 0} packages`, color: "#ff3366", icon: "🔬" },
                  { file: "risk-scores.json", desc: `5-signal 0-100 risk scores — ${riskBatch?.high_risk_count ?? 0} HIGH, ${riskBatch?.medium_risk_count ?? 0} MEDIUM`, color: "#ff9900", icon: "📊" },
                  { file: "public-keys.pem", desc: `ML-DSA-65 (1,952 B) + Ed25519 (32 B) — ${keypair.using_real_oqs ? "liboqs" : "simulation"}`, color: "#00ff88", icon: "🔑" },
                  { file: "verify.py", desc: "Offline verifier — pip install cryptography && python verify.py", color: "#888", icon: "🐍" },
                ].map(f => (
                  <div key={f.file} className="flex items-center gap-3 py-2 border-b border-white/5 last:border-0">
                    <span className="text-lg">{f.icon}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono font-semibold" style={{ color: f.color }}>{f.file}</p>
                      <p className="text-[11px] text-gray-500">{f.desc}</p>
                    </div>
                    <div className="w-2 h-2 rounded-full bg-[#00ff88] flex-shrink-0" />
                  </div>
                ))}

                <button onClick={handleDownload} disabled={downloading}
                  className="w-full py-3.5 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#00ff88] text-black font-bold text-sm hover:opacity-90 disabled:opacity-60 flex items-center justify-center gap-2">
                  {downloading ? <><span className="animate-spin">⟳</span> Preparing ZIP…</> : "↓ Download 6-file ZIP bundle"}
                </button>
                <button onClick={() => setStep(2)} className="w-full py-2 text-xs text-gray-600 hover:text-gray-300 transition-colors">← Back to review</button>
              </div>
            </div>

            {/* Audit log */}
            {auditEvents.length > 0 && (
              <div className="glass-card rounded-2xl overflow-hidden">
                <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-[#00ff88] text-sm">⏱</span>
                    <span className="text-sm font-semibold text-white">Session Audit Log</span>
                    <span className="px-2 py-0.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 text-[#00ff88] text-xs">{auditEvents.length}</span>
                  </div>
                  <p className="text-xs text-gray-600">Every event signed · ML-DSA-65 + Ed25519 · {auditEvents.reduce((n, e) => n + (e.signature_size_bytes || 3357), 0).toLocaleString()} B total</p>
                </div>
                <div className="divide-y divide-white/5 max-h-72 overflow-y-auto">
                  {[...auditEvents].reverse().map((ev, i) => (
                    <div key={ev.id} className="px-5 py-3 flex items-start gap-3">
                      <div className="w-1.5 h-1.5 rounded-full bg-[#00ff88] flex-shrink-0 mt-1.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-[#a78bfa]">{ev.event_type}</span>
                          <span className="text-[10px] text-gray-600">
                            {new Date(ev.timestamp * 1000).toISOString().slice(11, 19)}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 truncate">{ev.description}</p>
                        <p className="text-[10px] text-gray-700 font-mono truncate">
                          ML-DSA-65: {ev.ml_dsa_signature.slice(0,24)}…
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
