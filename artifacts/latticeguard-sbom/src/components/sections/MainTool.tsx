import { useState, useCallback, useRef } from "react";
import JSZip from "jszip";
import { resolveDependencies, manualLookup, ResolvedPackage, PackageFile, ManualResult } from "@/api/packages";
import { generateKeypair, signAllComponents, SBOM, KeygenResult } from "@/api/signing";

const PYPI_PLACEHOLDER = `requests==2.31.0
cryptography==42.0.0
flask==2.3.3`;

const NPM_PLACEHOLDER = `{
  "dependencies": {
    "express": "^4.18.2",
    "axios": "^1.6.0"
  }
}`;

const VERIFY_SCRIPT = `#!/usr/bin/env python3
import json, sys, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify_sbom(path):
    with open(path) as f:
        sbom = json.load(f)
    print(f"\\nLatticeGuard SBOM Verification — Serial: {sbom.get('serial_number','')}")
    all_ok = True
    for item in sbom["components"]:
        comp = item["component"]
        label = f"{comp['name']}@{comp['version']}"
        canonical = json.dumps(comp, sort_keys=True)
        computed = hashlib.sha256(canonical.encode()).digest()
        hash_ok = computed.hex() == item["sha256_signed"]
        ed25519_ok = False
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(item["public_key_ed25519"]))
            pub.verify(bytes.fromhex(item["ed25519_signature"]), computed)
            ed25519_ok = True
        except Exception:
            pass
        ok = hash_ok and ed25519_ok
        all_ok = all_ok and ok
        print(f"  {'\\u2705' if ok else '\\u274c'}  {label}  SHA256:{'OK' if hash_ok else 'FAIL'}  Ed25519:{'OK' if ed25519_ok else 'FAIL'}")
    print(f"\\nResult: {'SAFE' if all_ok else 'TAMPERED'}\\n")
    return all_ok

if __name__ == "__main__":
    ok = verify_sbom(sys.argv[1] if len(sys.argv) > 1 else "latticeguard-sbom.json")
    sys.exit(0 if ok else 1)
`;

function fmt(bytes: number) {
  if (bytes === 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

const FILE_TYPE_STYLE: Record<string, { bg: string; text: string; label: string }> = {
  wheel:     { bg: "bg-[#00d4ff]/10 border-[#00d4ff]/30", text: "text-[#00d4ff]", label: "WHEEL" },
  sdist:     { bg: "bg-[#7c3aed]/10 border-[#7c3aed]/30", text: "text-[#a78bfa]", label: "SDIST" },
  egg:       { bg: "bg-yellow-900/20 border-yellow-700/30", text: "text-yellow-400", label: "EGG" },
  installer: { bg: "bg-orange-900/20 border-orange-700/30", text: "text-orange-400", label: "EXE/MSI" },
  other:     { bg: "bg-white/5 border-white/10", text: "text-gray-400", label: "FILE" },
};

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "text-[#ff3366] bg-[#ff3366]/10 border-[#ff3366]/30",
  HIGH:     "text-orange-400 bg-orange-400/10 border-orange-400/30",
  MEDIUM:   "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  LOW:      "text-gray-400 bg-white/5 border-white/10",
  UNKNOWN:  "text-gray-500 bg-white/5 border-white/10",
};

function FileTypeBadge({ type }: { type: string }) {
  const s = FILE_TYPE_STYLE[type] ?? FILE_TYPE_STYLE.other;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${s.bg} ${s.text}`}>
      {s.label}
    </span>
  );
}

const OS_LABELS: Record<string, string> = {
  linux: "🐧 Linux",
  macos: "🍎 macOS",
  windows: "🪟 Windows",
  any: "Any",
  other: "Other",
};

const PYTHON_VER_MAP: Record<string, string> = {
  cp310: "3.10", cp311: "3.11", cp312: "3.12", cp313: "3.13",
  cp39: "3.9", cp38: "3.8", cp37: "3.7", py3: "3.x", py2: "2.x",
};

function pyTagLabel(tag: string): string {
  return PYTHON_VER_MAP[tag] ?? tag;
}

function wheelMatchesPy(file: PackageFile, pyVer: string): boolean {
  if (!file.python_tag || pyVer === "all") return true;
  const tags = file.python_tag.split(".");
  return tags.some((t) => t === pyVer || t === "py3" || t === "py2");
}

function wheelMatchesOs(file: PackageFile, os: string): boolean {
  if (os === "all") return true;
  return file.platform_os === os || file.platform_os === "any";
}

function PackageCard({ pkg, onRemove }: { pkg: ResolvedPackage; onRemove?: () => void }) {
  const [showFiles, setShowFiles] = useState(false);
  const [pyFilter, setPyFilter] = useState("all");
  const [osFilter, setOsFilter] = useState("all");

  const c = pkg.component;
  const hasCVEs = pkg.cves.length > 0;

  const wheels = c.files.filter((f) => f.file_type === "wheel");
  const sdists = c.files.filter((f) => f.file_type === "sdist");
  const others = c.files.filter((f) => f.file_type !== "wheel" && f.file_type !== "sdist");

  // Available python versions across all wheels
  const availablePyTags = Array.from(
    new Set(wheels.flatMap((f) => (f.python_tag ?? "").split(".").filter(Boolean)))
  ).filter((t) => t.startsWith("cp") || t === "py3").sort();

  // Available OSes across all wheels
  const availableOses = Array.from(
    new Set(wheels.map((f) => f.platform_os ?? "any").filter((o) => o !== "any"))
  ).sort();

  const matchedWheels = wheels.filter(
    (f) => wheelMatchesPy(f, pyFilter) && wheelMatchesOs(f, osFilter)
  );
  const wouldInstall = matchedWheels[0] ?? null;
  const isFiltered = pyFilter !== "all" || osFilter !== "all";
  const matchCount = matchedWheels.length + sdists.length;

  return (
    <div className="rounded-xl border border-white/10 bg-black/30 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 flex items-start gap-3">
        <div className="shrink-0 mt-0.5">
          <div className={`w-2 h-2 rounded-full mt-1.5 ${hasCVEs ? "bg-[#ff3366]" : "bg-[#00ff88]"}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="font-mono font-semibold text-white text-sm">{c.name}</span>
            <span className="font-mono text-[#00d4ff] text-sm">@{c.version}</span>
            <span className="text-[10px] uppercase text-gray-600 tracking-wide font-medium">{c.ecosystem}</span>
            {hasCVEs ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold text-[#ff3366] bg-[#ff3366]/10 border border-[#ff3366]/30">
                {pkg.cves.length} CVE{pkg.cves.length !== 1 ? "s" : ""}
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold text-[#00ff88] bg-[#00ff88]/10 border border-[#00ff88]/30">
                clean
              </span>
            )}
          </div>
          {c.description && <p className="text-gray-500 text-xs mt-0.5 line-clamp-1">{c.description}</p>}
          <div className="flex items-center gap-3 mt-1 text-[11px] text-gray-600 flex-wrap">
            {c.license && c.license !== "Unknown" && <span>{c.license}</span>}
            {c.author && c.author !== "Unknown" && <span>by {c.author}</span>}
            {pkg.transitive_count > 0 && <span className="text-[#7c3aed]">+{pkg.transitive_count} transitive</span>}
          </div>
        </div>
        {onRemove && (
          <button onClick={onRemove} className="shrink-0 text-gray-700 hover:text-gray-400 text-xs transition-colors">✕</button>
        )}
      </div>

      {/* Distribution files */}
      {c.file_count > 0 && (
        <div className="border-t border-white/5 bg-black/20">
          {/* Section header + filter controls */}
          <div className="px-4 py-2.5 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-gray-400">📦 DISTRIBUTION FILES</span>
              <span className="px-1.5 py-0.5 rounded bg-white/5 text-[10px] font-mono text-gray-500">
                {isFiltered ? `${matchCount} of ${c.file_count}` : c.file_count} file{c.file_count !== 1 ? "s" : ""}
              </span>
              <div className="flex gap-1">
                {c.file_types.map((t) => <FileTypeBadge key={t} type={t} />)}
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              {availablePyTags.length > 1 && (
                <select
                  value={pyFilter}
                  onChange={(e) => setPyFilter(e.target.value)}
                  className="text-[10px] font-mono bg-black/50 border border-white/10 rounded px-2 py-1 text-gray-400 focus:outline-none focus:border-[#00d4ff]/40 cursor-pointer"
                >
                  <option value="all">All Python</option>
                  {availablePyTags.map((t) => (
                    <option key={t} value={t}>Python {pyTagLabel(t)}</option>
                  ))}
                </select>
              )}
              {availableOses.length > 1 && (
                <select
                  value={osFilter}
                  onChange={(e) => setOsFilter(e.target.value)}
                  className="text-[10px] font-mono bg-black/50 border border-white/10 rounded px-2 py-1 text-gray-400 focus:outline-none focus:border-[#00d4ff]/40 cursor-pointer"
                >
                  <option value="all">All OS</option>
                  {availableOses.map((os) => (
                    <option key={os} value={os}>{OS_LABELS[os] ?? os}</option>
                  ))}
                </select>
              )}
              <button
                onClick={() => setShowFiles(!showFiles)}
                className="text-[10px] text-gray-600 hover:text-gray-400 transition-colors px-1"
              >
                {showFiles ? "▲" : "▼"}
              </button>
            </div>
          </div>

          {/* "Would install" banner — shown when filter is active and there's a match */}
          {isFiltered && wouldInstall && (
            <div className="mx-4 mb-2 rounded-lg border border-[#00ff88]/30 bg-[#00ff88]/5 px-3 py-2 flex items-center gap-2">
              <span className="text-[#00ff88] text-[10px] font-bold shrink-0">✓ pip would install:</span>
              <span className="font-mono text-[11px] text-[#00ff88] truncate">{wouldInstall.filename}</span>
              <span className="shrink-0 text-[10px] text-gray-500">· {fmt(wouldInstall.size_bytes)}</span>
            </div>
          )}
          {isFiltered && !wouldInstall && (
            <div className="mx-4 mb-2 rounded-lg border border-[#ffaa00]/30 bg-[#ffaa00]/5 px-3 py-2">
              <span className="text-[#ffaa00] text-[10px]">No wheel matches this platform — pip would fall back to the sdist and compile from source.</span>
            </div>
          )}

          {/* Collapsed summary */}
          {!showFiles && (
            <div className="px-4 pb-3 space-y-2">
              {!isFiltered && wheels.length > 0 && (
                <>
                  {/* Platform group summary */}
                  <div className="flex flex-wrap gap-2">
                    {availableOses.map((os) => {
                      const count = wheels.filter((f) => f.platform_os === os).length;
                      return count > 0 ? (
                        <span key={os} className="text-[10px] font-mono px-2.5 py-1 rounded border bg-white/5 border-white/10 text-gray-400">
                          {OS_LABELS[os]} <span className="text-[#00d4ff] font-bold">{count}</span>
                        </span>
                      ) : null;
                    })}
                    {sdists.length > 0 && (
                      <span className="text-[10px] font-mono px-2.5 py-1 rounded border bg-[#7c3aed]/10 border-[#7c3aed]/30 text-[#a78bfa]">
                        Source dist <span className="font-bold">{sdists.length}</span>
                      </span>
                    )}
                  </div>
                  {availablePyTags.length > 1 && (
                    <p className="text-[10px] text-gray-600">
                      Python versions: {availablePyTags.map((t) => pyTagLabel(t)).join(", ")} — select Python + OS above to see which file pip would pick
                    </p>
                  )}
                </>
              )}
              {/* When filtered: show matching pills */}
              {isFiltered && matchedWheels.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {matchedWheels.map((f, i) => (
                    <span
                      key={i}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                        i === 0
                          ? "bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]"
                          : "bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]"
                      }`}
                    >
                      {i === 0 && <span className="text-[9px]">✓</span>}
                      {f.filename.length > 38 ? f.filename.slice(0, 36) + "…" : f.filename}
                      <span className="opacity-60">· {fmt(f.size_bytes)}</span>
                    </span>
                  ))}
                </div>
              )}
              {isFiltered && wheels.filter((f) => !matchedWheels.includes(f)).length > 0 && (
                <p className="text-[10px] text-gray-700 pl-1">
                  + {wheels.filter((f) => !matchedWheels.includes(f)).length} wheel{wheels.filter((f) => !matchedWheels.includes(f)).length !== 1 ? "s" : ""} for other platforms hidden
                </p>
              )}
              {/* Sdist always shown when filtered */}
              {isFiltered && sdists.map((f, i) => (
                <span key={i} className="inline-flex text-[10px] font-mono px-2 py-0.5 rounded border bg-[#7c3aed]/10 border-[#7c3aed]/30 text-[#a78bfa] mr-1">
                  {f.filename.length > 38 ? f.filename.slice(0, 36) + "…" : f.filename}
                  <span className="opacity-60 ml-1">· {fmt(f.size_bytes)}</span>
                </span>
              ))}
            </div>
          )}

          {/* Expanded list */}
          {showFiles && (
            <div className="px-4 pb-3 space-y-3">
              {/* Matched wheels */}
              {matchedWheels.length > 0 && (
                <div className="space-y-1.5">
                  {availableOses.length > 1 && (
                    <p className="text-[10px] text-gray-600 uppercase tracking-wide">
                      Matching wheels ({matchedWheels.length})
                    </p>
                  )}
                  {matchedWheels.map((f, i) => (
                    <FileRow key={i} file={f} isWouldInstall={i === 0 && isFiltered} />
                  ))}
                </div>
              )}

              {/* Non-matching wheels (dimmed) */}
              {isFiltered && (() => {
                const nonMatching = wheels.filter((f) => !matchedWheels.includes(f));
                return nonMatching.length > 0 ? (
                  <details className="group">
                    <summary className="text-[10px] text-gray-600 cursor-pointer hover:text-gray-400 transition-colors list-none flex items-center gap-1">
                      <span className="group-open:hidden">▶</span>
                      <span className="hidden group-open:inline">▼</span>
                      Show {nonMatching.length} other-platform wheel{nonMatching.length !== 1 ? "s" : ""} (not for your filter)
                    </summary>
                    <div className="mt-1.5 space-y-1.5 opacity-40">
                      {nonMatching.map((f, i) => <FileRow key={i} file={f} />)}
                    </div>
                  </details>
                ) : null;
              })()}

              {/* Sdist */}
              {sdists.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-[10px] text-gray-600 uppercase tracking-wide">Source distribution</p>
                  {sdists.map((f, i) => <FileRow key={i} file={f} />)}
                </div>
              )}

              {/* Other files */}
              {others.map((f, i) => <FileRow key={i} file={f} />)}
            </div>
          )}
        </div>
      )}

      {/* CVEs */}
      {hasCVEs && (
        <div className="border-t border-white/5 px-4 py-2 space-y-1.5">
          <p className="text-[10px] font-semibold text-[#ff3366] uppercase tracking-wide">Vulnerabilities</p>
          {pkg.cves.map((cve) => (
            <div key={cve.id} className="flex items-start gap-2 text-xs">
              <span className={`shrink-0 px-1.5 py-0.5 rounded border font-mono font-bold text-[10px] ${SEVERITY_STYLE[cve.severity] ?? SEVERITY_STYLE.UNKNOWN}`}>
                {cve.severity}
              </span>
              <span className="text-gray-300 font-mono shrink-0">{cve.id}</span>
              <span className="text-gray-500 line-clamp-1">{cve.summary}</span>
              {cve.fixed_in && <span className="shrink-0 text-[#00ff88] text-[10px]">fix→{cve.fixed_in}</span>}
            </div>
          ))}
        </div>
      )}

      {/* Dependencies */}
      {c.dependencies.length > 0 && (
        <div className="border-t border-white/5 px-4 py-2">
          <p className="text-[10px] text-gray-600 mb-1.5">Direct dependencies ({c.dependencies.length})</p>
          <div className="flex flex-wrap gap-1">
            {c.dependencies.slice(0, 15).map((d) => (
              <span key={d} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#7c3aed]/10 text-[#a78bfa] border border-[#7c3aed]/20">{d}</span>
            ))}
            {c.dependencies.length > 15 && (
              <span className="text-[10px] text-gray-600 self-center">+{c.dependencies.length - 15} more</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function FileRow({ file, isWouldInstall = false }: { file: PackageFile; isWouldInstall?: boolean }) {
  const s = FILE_TYPE_STYLE[file.file_type] ?? FILE_TYPE_STYLE.other;
  return (
    <div className={`rounded-lg border p-2.5 ${isWouldInstall ? "border-[#00ff88]/30 bg-[#00ff88]/5" : "border-white/5 bg-black/30"}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <FileTypeBadge type={file.file_type} />
        {isWouldInstall && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/30">
            ✓ WOULD INSTALL
          </span>
        )}
        <span className="font-mono text-[11px] text-gray-300 break-all">{file.filename}</span>
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-[10px] font-mono">
        <span className="text-gray-600"><span className="text-gray-500">size:</span> {fmt(file.size_bytes)}</span>
        {file.python_tag && (
          <span className="text-gray-600"><span className="text-gray-500">python:</span> {file.python_tag}</span>
        )}
        {file.platform_os && file.platform_os !== "any" && (
          <span className="text-gray-600"><span className="text-gray-500">os:</span> {OS_LABELS[file.platform_os] ?? file.platform_os}</span>
        )}
        {file.platform_arch && file.platform_arch !== "any" && (
          <span className="text-gray-600"><span className="text-gray-500">arch:</span> {file.platform_arch}</span>
        )}
        {file.requires_python && (
          <span className="text-gray-600"><span className="text-gray-500">requires python:</span> {file.requires_python}</span>
        )}
        <span className={`${s.text} opacity-60`}><span className="text-gray-500">sha256:</span> {file.sha256.slice(0, 20)}…</span>
      </div>
    </div>
  );
}

export default function MainTool() {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [ecosystem, setEcosystem] = useState<"pypi" | "npm">("pypi");
  const [inputMode, setInputMode] = useState<"paste" | "manual">("paste");
  const [rawInput, setRawInput] = useState("");
  const [packages, setPackages] = useState<ResolvedPackage[]>([]);
  const [errors, setErrors] = useState<{ package: string; error: string }[]>([]);
  const [keypair, setKeypair] = useState<KeygenResult | null>(null);
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [signingProgress, setSigningProgress] = useState(0);
  const [downloading, setDownloading] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  const [manualName, setManualName] = useState("");
  const [manualVersion, setManualVersion] = useState("");
  const [manualResult, setManualResult] = useState<ManualResult | null>(null);
  const [manualLoading, setManualLoading] = useState(false);
  const manualDebounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  const checkBackend = async () => {
    try {
      const r = await fetch("/latticeguard-api/health");
      if (r.ok) {
        const d = await r.json();
        setBackendOnline(true);
        return d;
      }
    } catch { /* empty */ }
    setBackendOnline(false);
    return null;
  };

  const handleResolve = useCallback(async () => {
    if (!rawInput.trim()) return;
    setLoading(true);
    setLoadingMsg("Connecting to backend…");
    setErrors([]);
    const health = await checkBackend();
    if (!health) {
      setLoading(false);
      return;
    }
    setLoadingMsg(`Fetching ${ecosystem.toUpperCase()} metadata + CVE data…`);
    try {
      const result = await resolveDependencies(rawInput, ecosystem);
      setPackages(result.components);
      setErrors(result.errors.map((e) => ({ package: e.package, error: e.error })));
      if (result.components.length > 0) setStep(2);
    } catch (e: unknown) {
      setErrors([{ package: "request", error: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
      setLoadingMsg("");
    }
  }, [rawInput, ecosystem]);

  const handleManualLookup = useCallback(async (name: string, version: string) => {
    if (!name.trim()) { setManualResult(null); return; }
    setManualLoading(true);
    try {
      const [res] = await manualLookup([{ name: name.trim(), version: version.trim() || undefined, ecosystem }]);
      setManualResult(res);
    } catch {
      setManualResult({ status: "error", package: name, message: "Backend unavailable" });
    } finally {
      setManualLoading(false);
    }
  }, [ecosystem]);

  const scheduleManualLookup = (name: string, version: string) => {
    setManualName(name);
    setManualVersion(version);
    if (manualDebounce.current) clearTimeout(manualDebounce.current);
    manualDebounce.current = setTimeout(() => handleManualLookup(name, version), 600);
  };

  const addManualPackage = () => {
    if (manualResult?.status === "found" && manualResult.component) {
      const c = manualResult.component;
      const exists = packages.some((p) => p.component.name === c.name && p.component.version === c.version);
      if (!exists) {
        setPackages((prev) => [...prev, { component: c, cves: manualResult.cves ?? [], transitive_count: 0, transitive: [] }]);
        if (packages.length === 0) setStep(2);
      }
      setManualName("");
      setManualVersion("");
      setManualResult(null);
    }
  };

  const handleKeygen = async () => {
    setLoading(true);
    setLoadingMsg("Generating ML-DSA-65 + Ed25519 keypair…");
    const health = await checkBackend();
    if (!health) { setLoading(false); return; }
    try {
      const kp = await generateKeypair();
      setKeypair(kp);
    } catch (e: unknown) {
      setErrors([{ package: "keygen", error: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
      setLoadingMsg("");
    }
  };

  const handleSign = async () => {
    if (!keypair || packages.length === 0) return;
    setLoading(true);
    setSigningProgress(0);
    setLoadingMsg("Signing components…");
    try {
      const result = await signAllComponents(packages);
      setSbom(result);
      setSigningProgress(100);
      setStep(3);
    } catch (e: unknown) {
      setErrors([{ package: "sign", error: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
      setLoadingMsg("");
    }
  };

  const handleDownload = async () => {
    if (!sbom || !keypair) return;
    setDownloading(true);
    const zip = new JSZip();
    zip.file("latticeguard-sbom.json", JSON.stringify(sbom, null, 2));
    zip.file("public-keys.json", JSON.stringify({
      algorithm: "Hybrid(ML-DSA-65 + Ed25519)",
      standard: "NIST FIPS 204",
      security_level: keypair.security_level,
      ml_dsa_65: { public_key_hex: keypair.ml_dsa_public_key, public_key_bytes: keypair.ml_dsa_public_key_size, signature_bytes: 3293 },
      ed25519: { public_key_hex: keypair.ed25519_public_key, public_key_bytes: 32, signature_bytes: 64 },
      generated_at: new Date(keypair.generated_at * 1000).toISOString(),
    }, null, 2));
    zip.file("verify.py", VERIFY_SCRIPT);
    const totalCVEs = sbom.components.reduce((n, c) => n + c.cves.length, 0);
    zip.file("README.txt", [
      "LatticeGuard SBOM Bundle",
      "═".repeat(50),
      `Generated : ${new Date(parseFloat(sbom.generated_at) * 1000).toUTCString()}`,
      `Serial    : ${sbom.serial_number}`,
      `Format    : CycloneDX ${sbom.spec_version}`,
      `Algorithm : ${sbom.algorithm}`,
      `Standard  : ${sbom.fips_standard}`,
      `Components: ${sbom.total_components}  |  CVEs: ${totalCVEs}`,
      "",
      ...sbom.components.map((c) =>
        `  ${c.component.name}@${c.component.version}\n    PURL: ${c.component.purl}\n    CVEs: ${c.cves.map((cv) => cv.id).join(", ") || "none"}`
      ),
      "",
      "Verify: pip install cryptography && python verify.py latticeguard-sbom.json",
    ].join("\n"));
    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `latticeguard-sbom-${Date.now()}.zip`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloading(false);
  };

  const totalCVEs = packages.reduce((a, p) => a + p.cves.length, 0);

  return (
    <section id="tool" className="py-20 px-4">
      <div className="max-w-4xl mx-auto space-y-6">

        {/* ─── HEADER ─── */}
        <div className="text-center mb-2">
          <h2 className="text-3xl md:text-4xl font-bold mb-2">
            <span className="gradient-text">SBOM Generator</span>
          </h2>
          <p className="text-gray-500 text-sm max-w-lg mx-auto">
            Resolve real packages from PyPI or npm, inspect every distribution file, check live CVEs, then sign with post-quantum cryptography.
          </p>
          {backendOnline === false && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#ff3366]/10 border border-[#ff3366]/30 text-[#ff3366] text-xs">
              ● Backend offline — start the Python workflow
            </div>
          )}
          {backendOnline === true && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] text-xs">
              ● Backend connected
            </div>
          )}
        </div>

        {/* ─── STEP INDICATOR ─── */}
        <div className="flex items-center gap-0 justify-center">
          {[
            { n: 1, label: "Add Packages", done: packages.length > 0 },
            { n: 2, label: "Review & Sign", done: sbom !== null },
            { n: 3, label: "Export Bundle", done: false },
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

        {/* ══════════════════════════════════
            PANEL 1 — ADD PACKAGES
        ══════════════════════════════════ */}
        {step === 1 && (
          <div className="glass-card rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
              <div className="w-7 h-7 rounded-full border border-[#00d4ff] bg-[#00d4ff]/10 flex items-center justify-center text-xs font-bold text-[#00d4ff]">1</div>
              <h3 className="font-semibold text-white">Add Packages</h3>
            </div>

            <div className="p-5 space-y-5">
              {/* Ecosystem + Mode toggles */}
              <div className="flex flex-wrap gap-3">
                <div className="flex rounded-lg overflow-hidden border border-white/10 text-sm">
                  {(["pypi", "npm"] as const).map((eco) => (
                    <button
                      key={eco}
                      onClick={() => setEcosystem(eco)}
                      className={`px-4 py-2 font-mono font-medium transition-colors ${ecosystem === eco ? "bg-[#00d4ff]/15 text-[#00d4ff]" : "text-gray-500 hover:text-gray-300"}`}
                    >
                      {eco.toUpperCase()}
                    </button>
                  ))}
                </div>
                <div className="flex rounded-lg overflow-hidden border border-white/10 text-sm">
                  {(["paste", "manual"] as const).map((mode) => (
                    <button
                      key={mode}
                      onClick={() => setInputMode(mode)}
                      className={`px-4 py-2 transition-colors ${inputMode === mode ? "bg-[#7c3aed]/15 text-[#a78bfa]" : "text-gray-500 hover:text-gray-300"}`}
                    >
                      {mode === "paste" ? "Paste file" : "Add manually"}
                    </button>
                  ))}
                </div>
              </div>

              {/* ── PASTE MODE ── */}
              {inputMode === "paste" && (
                <div className="space-y-3">
                  <label className="text-xs text-gray-500 block">
                    {ecosystem === "pypi" ? "Paste your requirements.txt contents:" : "Paste your package.json contents:"}
                  </label>
                  <textarea
                    value={rawInput}
                    onChange={(e) => setRawInput(e.target.value)}
                    placeholder={ecosystem === "pypi" ? PYPI_PLACEHOLDER : NPM_PLACEHOLDER}
                    rows={5}
                    className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40 resize-y"
                  />
                  <button
                    onClick={handleResolve}
                    disabled={loading || !rawInput.trim()}
                    className="w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <><span className="animate-spin">⟳</span> {loadingMsg}</>
                    ) : (
                      "Resolve packages & check CVEs →"
                    )}
                  </button>
                </div>
              )}

              {/* ── MANUAL MODE ── */}
              {inputMode === "manual" && (
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="text-xs text-gray-500 mb-1 block">Package name</label>
                      <input
                        value={manualName}
                        onChange={(e) => scheduleManualLookup(e.target.value, manualVersion)}
                        placeholder={ecosystem === "pypi" ? "flask" : "express"}
                        className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40"
                      />
                    </div>
                    <div className="w-36">
                      <label className="text-xs text-gray-500 mb-1 block">Version (optional)</label>
                      <input
                        value={manualVersion}
                        onChange={(e) => scheduleManualLookup(manualName, e.target.value)}
                        placeholder="latest"
                        className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40"
                      />
                    </div>
                  </div>
                  {manualLoading && <p className="text-xs text-[#00d4ff] animate-pulse">Looking up {ecosystem} registry…</p>}
                  {manualResult && !manualLoading && (
                    <div className={`rounded-lg p-3 text-sm border ${manualResult.status === "found" ? "border-[#00ff88]/30 bg-[#00ff88]/5" : "border-[#ff3366]/30 bg-[#ff3366]/5"}`}>
                      {manualResult.status === "found" && manualResult.component ? (
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="font-mono font-semibold text-[#00ff88]">{manualResult.component.name}@{manualResult.component.version}</p>
                            <p className="text-gray-400 text-xs mt-0.5 line-clamp-1">{manualResult.component.description}</p>
                            <div className="flex gap-2 text-xs text-gray-600 mt-1 flex-wrap">
                              {manualResult.component.file_count > 0 && (
                                <span>{manualResult.component.file_count} files ({manualResult.component.file_types.join(", ")})</span>
                              )}
                              {(manualResult.cves?.length ?? 0) > 0 && (
                                <span className="text-[#ff3366]">⚠ {manualResult.cves!.length} CVEs</span>
                              )}
                            </div>
                          </div>
                          <button
                            onClick={addManualPackage}
                            className="shrink-0 px-3 py-1.5 bg-[#00d4ff]/15 hover:bg-[#00d4ff]/25 border border-[#00d4ff]/40 rounded text-[#00d4ff] text-xs font-medium transition-colors"
                          >
                            + Add
                          </button>
                        </div>
                      ) : (
                        <div>
                          <p className="text-[#ff3366] text-xs">{manualResult.message}</p>
                          {manualResult.available_versions && manualResult.available_versions.length > 0 && (
                            <div className="mt-2">
                              <p className="text-gray-500 text-xs mb-1">Available versions:</p>
                              <div className="flex flex-wrap gap-1">
                                {manualResult.available_versions.map((v) => (
                                  <button key={v} onClick={() => scheduleManualLookup(manualName, v)} className="px-2 py-0.5 text-xs bg-white/5 hover:bg-white/10 border border-white/10 rounded text-gray-300 font-mono transition-colors">{v}</button>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  {packages.length > 0 && (
                    <button
                      onClick={() => setStep(2)}
                      className="w-full py-2.5 rounded-xl border border-[#00d4ff]/30 text-[#00d4ff] text-sm font-medium hover:bg-[#00d4ff]/10 transition-colors"
                    >
                      Continue to review & sign →
                    </button>
                  )}
                </div>
              )}

              {/* Errors */}
              {errors.length > 0 && (
                <div className="rounded-lg border border-[#ff3366]/20 bg-[#ff3366]/5 p-3 space-y-1">
                  {errors.map((e, i) => (
                    <p key={i} className="text-xs text-[#ff3366] font-mono">✗ {e.package}: {e.error}</p>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════
            PANEL 2 — REVIEW & SIGN
        ══════════════════════════════════ */}
        {step === 2 && (
          <div className="space-y-5">
            {/* Review */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-full border border-[#00d4ff] bg-[#00d4ff]/10 flex items-center justify-center text-xs font-bold text-[#00d4ff]">2</div>
                  <div>
                    <h3 className="font-semibold text-white">Review Packages</h3>
                    <p className="text-xs text-gray-500">
                      {packages.length} resolved
                      {totalCVEs > 0 && <span className="text-[#ff3366] ml-2">· {totalCVEs} CVEs</span>}
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
                    key={`${pkg.component.name}-${pkg.component.version}-${i}`}
                    pkg={pkg}
                    onRemove={() => setPackages((prev) => prev.filter((_, idx) => idx !== i))}
                  />
                ))}
              </div>
            </div>

            {/* Sign */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border ${sbom ? "border-[#00ff88] bg-[#00ff88]/10 text-[#00ff88]" : "border-[#7c3aed] bg-[#7c3aed]/10 text-[#a78bfa]"}`}>
                  {sbom ? "✓" : "⊕"}
                </div>
                <h3 className="font-semibold text-white">Sign with Hybrid Post-Quantum Cryptography</h3>
              </div>

              <div className="p-5 space-y-4">
                {/* Algorithm cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-xl border border-[#7c3aed]/30 bg-[#7c3aed]/5 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-[#a78bfa] font-semibold text-sm">ML-DSA-65</p>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-[#7c3aed]/20 border border-[#7c3aed]/30 text-[#a78bfa] font-mono">POST-QUANTUM</span>
                    </div>
                    <p className="text-gray-500 text-xs">NIST FIPS 204 · Security Level 3</p>
                    <p className="text-gray-500 text-xs">Hard problem: Module-LWE + SIS</p>
                    <div className="flex gap-3 text-xs font-mono text-gray-600 pt-1">
                      <span>pub key: 1,952 B</span>
                      <span>sig: 3,293 B</span>
                    </div>
                    {keypair && (
                      <div className="mt-1 bg-black/40 rounded p-2 font-mono text-[10px] text-[#a78bfa] break-all opacity-70">
                        {keypair.ml_dsa_public_key.slice(0, 48)}…
                        <span className="ml-1 text-gray-600">({keypair.using_real_oqs ? "liboqs" : "simulation"})</span>
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-[#00d4ff]/30 bg-[#00d4ff]/5 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-[#00d4ff] font-semibold text-sm">Ed25519</p>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] font-mono">REAL</span>
                    </div>
                    <p className="text-gray-500 text-xs">Classical · Edwards25519 curve</p>
                    <p className="text-gray-500 text-xs">Hybrid layer: breaks if either fails</p>
                    <div className="flex gap-3 text-xs font-mono text-gray-600 pt-1">
                      <span>pub key: 32 B</span>
                      <span>sig: 64 B</span>
                    </div>
                    {keypair && (
                      <div className="mt-1 bg-black/40 rounded p-2 font-mono text-[10px] text-[#00d4ff] break-all opacity-70">
                        {keypair.ed25519_public_key}
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                {!sbom ? (
                  <div className="flex flex-col sm:flex-row gap-3">
                    <button
                      onClick={handleKeygen}
                      disabled={loading || !!keypair}
                      className={`flex-1 py-3 rounded-xl border font-semibold text-sm transition-all flex items-center justify-center gap-2 ${
                        keypair
                          ? "border-[#00ff88]/40 text-[#00ff88] bg-[#00ff88]/5"
                          : "border-[#7c3aed]/50 text-[#a78bfa] hover:bg-[#7c3aed]/10 disabled:opacity-40"
                      }`}
                    >
                      {loading && loadingMsg.includes("keypair") ? (
                        <><span className="animate-spin">⟳</span> Generating…</>
                      ) : keypair ? (
                        "✓ Keypair generated"
                      ) : (
                        "① Generate keypair"
                      )}
                    </button>
                    <button
                      onClick={handleSign}
                      disabled={loading || !keypair || packages.length === 0}
                      className="flex-1 py-3 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#00d4ff] text-white font-semibold text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
                    >
                      {loading && loadingMsg.includes("Signing") ? (
                        <><span className="animate-spin">⟳</span> Signing {packages.length} components…</>
                      ) : (
                        `② Sign ${packages.length} component${packages.length !== 1 ? "s" : ""} →`
                      )}
                    </button>
                  </div>
                ) : (
                  <div className="rounded-xl border border-[#00ff88]/30 bg-[#00ff88]/5 p-4">
                    <p className="text-[#00ff88] font-semibold text-sm mb-1">✓ SBOM signed & sealed</p>
                    <div className="grid grid-cols-3 gap-3 text-center mt-3">
                      <div>
                        <p className="text-xl font-bold text-white">{sbom.total_components}</p>
                        <p className="text-xs text-gray-500">Components</p>
                      </div>
                      <div>
                        <p className="text-xl font-bold text-[#a78bfa]">3,293</p>
                        <p className="text-xs text-gray-500">Sig bytes (ML-DSA)</p>
                      </div>
                      <div>
                        <p className="text-xl font-bold text-[#ff3366]">{sbom.components.reduce((n, c) => n + c.cves.length, 0)}</p>
                        <p className="text-xs text-gray-500">CVEs</p>
                      </div>
                    </div>
                    <p className="text-xs text-gray-600 font-mono mt-3">Serial: {sbom.serial_number}</p>
                    <button
                      onClick={() => setStep(3)}
                      className="mt-3 w-full py-2.5 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#00ff88] text-black font-bold text-sm hover:opacity-90 transition-opacity"
                    >
                      Export bundle →
                    </button>
                  </div>
                )}

                {errors.length > 0 && (
                  <div className="rounded-lg border border-[#ff3366]/20 bg-[#ff3366]/5 p-3 space-y-1">
                    {errors.map((e, i) => (
                      <p key={i} className="text-xs text-[#ff3366] font-mono">✗ {e.package}: {e.error}</p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════
            PANEL 3 — EXPORT
        ══════════════════════════════════ */}
        {step === 3 && sbom && keypair && (
          <div className="glass-card rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
              <div className="w-7 h-7 rounded-full border border-[#00ff88] bg-[#00ff88]/10 flex items-center justify-center text-xs font-bold text-[#00ff88]">↓</div>
              <div>
                <h3 className="font-semibold text-white">Export Bundle</h3>
                <p className="text-xs text-gray-500">4 files ready to download</p>
              </div>
              <button onClick={() => setStep(2)} className="ml-auto text-xs text-gray-600 hover:text-gray-300 transition-colors">← Back</button>
            </div>

            <div className="p-5 space-y-4">
              {/* Bundle contents */}
              <div className="space-y-2">
                {[
                  { icon: "{}",  name: "latticeguard-sbom.json", desc: "Full SBOM with dual signatures for all components", color: "text-[#00d4ff]" },
                  { icon: "🔑", name: "public-keys.json",        desc: "ML-DSA-65 + Ed25519 public keys for offline verification", color: "text-[#a78bfa]" },
                  { icon: "🐍", name: "verify.py",               desc: "Python script to verify signatures without installing anything", color: "text-[#00ff88]" },
                  { icon: "📄", name: "README.txt",              desc: "Human-readable summary of all components and CVEs", color: "text-gray-400" },
                ].map((f) => (
                  <div key={f.name} className="flex items-center gap-3 p-3 rounded-lg bg-black/20 border border-white/5">
                    <span className="text-base w-6 text-center shrink-0">{f.icon}</span>
                    <div className="min-w-0">
                      <p className={`text-sm font-mono font-medium ${f.color}`}>{f.name}</p>
                      <p className="text-xs text-gray-600">{f.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Summary */}
              <div className="rounded-xl border border-white/10 bg-black/20 p-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
                <div>
                  <p className="text-xl font-bold text-white">{sbom.total_components}</p>
                  <p className="text-xs text-gray-500">Components</p>
                </div>
                <div>
                  <p className="text-xl font-bold text-[#00ff88]">{sbom.quantum_safe ? "Yes" : "No"}</p>
                  <p className="text-xs text-gray-500">Quantum-safe</p>
                </div>
                <div>
                  <p className="text-xl font-bold text-[#a78bfa]">{sbom.fips_standard}</p>
                  <p className="text-xs text-gray-500">Standard</p>
                </div>
                <div>
                  <p className="text-xl font-bold text-[#ff3366]">{sbom.components.reduce((n, c) => n + c.cves.length, 0)}</p>
                  <p className="text-xs text-gray-500">CVEs</p>
                </div>
              </div>

              {/* Offline verify hint */}
              <div className="rounded-lg border border-white/5 bg-black/30 p-3 font-mono text-xs space-y-1 text-gray-600">
                <p><span className="text-gray-500"># verify offline after download:</span></p>
                <p className="text-[#00ff88]">pip install cryptography</p>
                <p className="text-[#00d4ff]">python verify.py latticeguard-sbom.json</p>
              </div>

              <button
                onClick={handleDownload}
                disabled={downloading}
                className="w-full py-4 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-bold text-base disabled:opacity-60 hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
              >
                {downloading ? <><span className="animate-spin">⟳</span> Building ZIP…</> : "↓ Download latticeguard-sbom.zip"}
              </button>
            </div>
          </div>
        )}

      </div>
    </section>
  );
}
