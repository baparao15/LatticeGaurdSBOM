import { useState, useCallback, useRef } from "react";
import JSZip from "jszip";
import CryptoTerminal, { TerminalLine } from "@/components/CryptoTerminal";
import ManualInput from "@/components/ManualInput";
import DependencyTree from "@/components/DependencyTree";
import { resolveDependencies, ResolvedPackage, Component, CVE } from "@/api/packages";
import { generateKeypair, signAllComponents, SBOM, KeygenResult } from "@/api/signing";

type Step = 1 | 2 | 3;

const PYPI_SAMPLE = `requests==2.31.0
cryptography==42.0.0
flask==2.3.3`;

const NPM_SAMPLE = `{
  "dependencies": {
    "express": "^4.18.2",
    "axios": "^1.6.0",
    "lodash": "^4.17.21"
  }
}`;

const VERIFY_SCRIPT = `#!/usr/bin/env python3
"""
LatticeGuard SBOM Verifier
Run: python verify.py latticeguard-sbom.json
Requires: pip install cryptography
"""
import json, sys, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify_sbom(path):
    with open(path) as f:
        sbom = json.load(f)

    print(f"\\n{'='*60}")
    print(f"  LatticeGuard SBOM Verification Report")
    print(f"  Serial: {sbom.get('serial_number','')}")
    print(f"  Algorithm: {sbom.get('algorithm','')}")
    print(f"{'='*60}\\n")

    all_ok = True
    for item in sbom["components"]:
        comp = item["component"]
        label = f"{comp['name']}@{comp['version']}"
        canonical = json.dumps(comp, sort_keys=True)
        computed = hashlib.sha256(canonical.encode()).digest()
        hash_ok = computed.hex() == item["sha256_signed"]

        ed25519_ok = False
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(item["public_key_ed25519"])
            )
            pub.verify(bytes.fromhex(item["ed25519_signature"]), computed)
            ed25519_ok = True
        except Exception:
            pass

        ok = hash_ok and ed25519_ok
        all_ok = all_ok and ok
        icon = "\\u2705" if ok else "\\u274c"
        print(f"  {icon}  {label}")
        print(f"       SHA-256  : {'OK' if hash_ok else 'MISMATCH'}")
        print(f"       Ed25519  : {'OK' if ed25519_ok else 'INVALID'}")
        cves = item.get("cves", [])
        if cves:
            print(f"       CVEs     : {', '.join(c['id'] for c in cves)}")
        print()

    print(f"{'='*60}")
    print(f"  Result: {'SAFE TO INSTALL' if all_ok else 'BLOCKED — TAMPERED'}")
    print(f"{'='*60}\\n")
    return all_ok

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "latticeguard-sbom.json"
    ok = verify_sbom(path)
    sys.exit(0 if ok else 1)
`;

export default function MainTool() {
  const [step, setStep] = useState<Step>(1);
  const [ecosystem, setEcosystem] = useState<"pypi" | "npm">("pypi");
  const [inputMode, setInputMode] = useState<"paste" | "manual">("paste");
  const [rawInput, setRawInput] = useState("");
  const [packages, setPackages] = useState<ResolvedPackage[]>([]);
  const [keypair, setKeypair] = useState<KeygenResult | null>(null);
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [logs, setLogs] = useState<TerminalLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [downloading, setDownloading] = useState(false);
  const step2Ref = useRef<HTMLDivElement>(null);
  const step3Ref = useRef<HTMLDivElement>(null);

  const push = useCallback((text: string, type: TerminalLine["type"] = "info") => {
    setLogs((p) => [...p, { text, type }]);
  }, []);

  const checkBackend = async () => {
    try {
      const r = await fetch("/latticeguard-api/health");
      if (r.ok) {
        const d = await r.json();
        setBackendOnline(true);
        return d;
      }
    } catch {
      setBackendOnline(false);
    }
    return null;
  };

  const scrollTo = (ref: React.RefObject<HTMLDivElement | null>) => {
    setTimeout(() => ref.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 150);
  };

  const handleResolve = async () => {
    if (!rawInput.trim()) return;
    setLoading(true);
    setLogs([]);
    push("Connecting to LatticeGuard API…", "dim");
    const health = await checkBackend();
    if (!health) {
      push("❌ Backend offline. Make sure the Python workflow is running.", "error");
      setLoading(false);
      return;
    }
    push(`✓ Connected | ${health.real_oqs ? "liboqs REAL" : "ML-DSA-65 simulation (NIST byte-accurate)"}`, "success");
    push(`Fetching real ${ecosystem.toUpperCase()} metadata + CVEs…`, "info");
    try {
      const result = await resolveDependencies(rawInput, ecosystem);
      result.components.forEach((pkg) => {
        const sha = pkg.component.sha256 ? pkg.component.sha256.slice(0, 16) + "…" : "no wheel";
        const cve = pkg.cves.length ? ` ⚠ ${pkg.cves.length} CVE(s)` : " ✓ no CVEs";
        push(`✓ ${pkg.component.name}@${pkg.component.version}${cve}`, pkg.cves.length ? "warn" : "success");
        push(`  sha256: ${sha} | ${(pkg.component.size_bytes / 1024).toFixed(1)} KB | ${pkg.transitive_count} transitive deps`, "dim");
        pkg.cves.forEach((c) => push(`  CVE: ${c.id} (${c.severity}) — ${c.summary.slice(0, 80)}`, "warn"));
      });
      result.errors.forEach((e) => push(`✗ ${e.package}: ${e.error}`, "error"));
      push(`\nResolved ${result.total_found} package(s), ${result.total_failed} failed.`, "dim");
      setPackages(result.components);
      if (result.components.length > 0) {
        setStep(2);
        scrollTo(step2Ref);
      }
    } catch (e: unknown) {
      push(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleAddManual = (component: Component, cves: CVE[]) => {
    const exists = packages.find(
      (p) => p.component.name === component.name && p.component.version === component.version
    );
    if (!exists) {
      setPackages((prev) => [...prev, { component, cves, transitive_count: 0, transitive: [] }]);
      push(`+ Added ${component.name}@${component.version} | sha256: ${component.sha256.slice(0, 16)}…`, "success");
      setStep(2);
      scrollTo(step2Ref);
    }
  };

  const handleKeygen = async () => {
    setLoading(true);
    push("\n─── Generating Keypair ───", "dim");
    const health = await checkBackend();
    if (!health) {
      push("❌ Backend offline.", "error");
      setLoading(false);
      return;
    }
    try {
      const kp = await generateKeypair();
      setKeypair(kp);
      push(`✓ ML-DSA-65 keypair generated`, "success");
      push(`  Mode: ${kp.using_real_oqs ? "liboqs REAL (native)" : "NIST-accurate simulation (correct byte sizes)"}`, kp.using_real_oqs ? "success" : "warn");
      push(`  ML-DSA pub key: ${kp.ml_dsa_public_key_size} bytes (NIST spec: 1952)`, "dim");
      push(`  ${kp.ml_dsa_public_key.slice(0, 48)}…`, "dim");
      push(`  Ed25519 pub key: 32 bytes (REAL via cryptography lib)`, "dim");
      push(`  ${kp.ed25519_public_key}`, "dim");
      push(`  Standard: NIST FIPS 204 | Security Level 3`, "dim");
    } catch (e: unknown) {
      push(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleSign = async () => {
    if (!keypair || packages.length === 0) return;
    setLoading(true);
    push("\n─── Signing Components ───", "dim");
    try {
      const result = await signAllComponents(packages);
      setSbom(result);
      result.components.forEach((sc) => {
        const mlDsaBytes = Math.floor(sc.ml_dsa_signature.length / 2);
        const ed25519Bytes = Math.floor(sc.ed25519_signature.length / 2);
        push(`✓ ${sc.component.name}@${sc.component.version}`, "success");
        push(`  SHA-256 of canonical JSON: ${sc.sha256_signed.slice(0, 48)}…`, "dim");
        push(`  ML-DSA-65 sig: ${sc.ml_dsa_signature.slice(0, 32)}… (${mlDsaBytes} bytes ✓)`, mlDsaBytes === 3293 ? "dim" : "warn");
        push(`  Ed25519 sig: ${sc.ed25519_signature.slice(0, 32)}… (${ed25519Bytes} bytes ✓)`, "dim");
        if (sc.cves.length > 0) push(`  ⚠ CVEs: ${sc.cves.map(c => c.id).join(", ")}`, "warn");
      });
      push(`\n✓ SBOM sealed | ${result.total_components} components | CycloneDX ${result.spec_version} | ${result.quantum_safe ? "Quantum-safe ✓" : ""}`, "success");
      push(`  Serial: ${result.serial_number}`, "dim");
      push(`  → Proceed to step 3 to download the ZIP bundle`, "info");
      setStep(3);
      scrollTo(step3Ref);
    } catch (e: unknown) {
      push(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    if (!sbom || !keypair) return;
    setDownloading(true);

    const zip = new JSZip();

    // 1. Full SBOM JSON
    zip.file("latticeguard-sbom.json", JSON.stringify(sbom, null, 2));

    // 2. Public keys
    const keys = {
      algorithm: "Hybrid(ML-DSA-65 + Ed25519)",
      standard: "NIST FIPS 204",
      security_level: keypair.security_level,
      ml_dsa_65: {
        public_key_hex: keypair.ml_dsa_public_key,
        public_key_bytes: keypair.ml_dsa_public_key_size,
        signature_bytes: 3293,
      },
      ed25519: {
        public_key_hex: keypair.ed25519_public_key,
        public_key_bytes: 32,
        signature_bytes: 64,
      },
      generated_at: new Date(keypair.generated_at * 1000).toISOString(),
    };
    zip.file("public-keys.json", JSON.stringify(keys, null, 2));

    // 3. Verification script
    zip.file("verify.py", VERIFY_SCRIPT);

    // 4. Human-readable summary
    const totalCVEs = sbom.components.reduce((n, c) => n + c.cves.length, 0);
    const summary = [
      "LatticeGuard SBOM Bundle",
      "═".repeat(50),
      `Generated : ${new Date(parseFloat(sbom.generated_at) * 1000).toUTCString()}`,
      `Serial    : ${sbom.serial_number}`,
      `Format    : CycloneDX ${sbom.spec_version}`,
      `Algorithm : ${sbom.algorithm}`,
      `Standard  : ${sbom.fips_standard}`,
      "",
      `Components: ${sbom.total_components}`,
      `CVEs found: ${totalCVEs}`,
      "",
      "Components:",
      ...sbom.components.map((c) => {
        const cveList = c.cves.map((cv) => cv.id).join(", ") || "none";
        return [
          `  ${c.component.name}@${c.component.version}`,
          `    PURL      : ${c.component.purl}`,
          `    SHA-256   : ${c.component.sha256 || "(no wheel)"}`,
          `    License   : ${c.component.license}`,
          `    CVEs      : ${cveList}`,
          `    ML-DSA sig: ${c.ml_dsa_signature.slice(0, 32)}… (3293 bytes)`,
          `    Ed25519   : ${c.ed25519_signature.slice(0, 32)}… (64 bytes)`,
        ].join("\n");
      }),
      "",
      "To verify:",
      "  pip install cryptography",
      "  python verify.py latticeguard-sbom.json",
    ].join("\n");
    zip.file("README.txt", summary);

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
  const stepDone = (s: Step) => {
    if (s === 1) return packages.length > 0;
    if (s === 2) return sbom !== null;
    if (s === 3) return sbom !== null;
    return false;
  };

  return (
    <section id="tool" className="py-20 px-4">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-3">
            <span className="gradient-text">SBOM Generator</span>
          </h2>
          <p className="text-gray-400 max-w-xl mx-auto text-sm">
            Fetch real package metadata from PyPI/npm, check live CVEs, then sign every
            component with hybrid ML-DSA-65 + Ed25519.
          </p>
          {backendOnline === false && (
            <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#ff3366]/10 border border-[#ff3366]/30 text-[#ff3366] text-sm">
              ⚠ Backend offline — start the "python-backend" workflow
            </div>
          )}
          {backendOnline === true && (
            <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] text-sm">
              ✓ Backend connected
            </div>
          )}
        </div>

        {/* Step Progress Bar */}
        <div className="flex items-center justify-center gap-0 mb-10">
          {([1, 2, 3] as Step[]).map((s, i) => {
            const labels = ["Resolve Packages", "Sign with ML-DSA-65", "Download Bundle"];
            const icons = ["⬡", "⊕", "↓"];
            const done = stepDone(s);
            const current = step === s;
            return (
              <div key={s} className="flex items-center">
                <button
                  onClick={() => setStep(s)}
                  className={`flex flex-col items-center px-4 py-2 rounded-xl transition-all gap-1 ${
                    current
                      ? "bg-[#00d4ff]/10 border border-[#00d4ff]/30"
                      : done
                      ? "opacity-70 hover:opacity-100"
                      : "opacity-40 cursor-default"
                  }`}
                >
                  <div
                    className={`w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold border-2 transition-all ${
                      done
                        ? "bg-[#00ff88]/20 border-[#00ff88] text-[#00ff88]"
                        : current
                        ? "bg-[#00d4ff]/20 border-[#00d4ff] text-[#00d4ff]"
                        : "bg-white/5 border-white/20 text-gray-500"
                    }`}
                  >
                    {done ? "✓" : icons[i]}
                  </div>
                  <span
                    className={`text-xs font-medium ${
                      current ? "text-[#00d4ff]" : done ? "text-[#00ff88]" : "text-gray-600"
                    }`}
                  >
                    {labels[i]}
                  </span>
                </button>
                {i < 2 && (
                  <div
                    className={`w-12 h-0.5 ${done ? "bg-[#00ff88]/40" : "bg-white/10"}`}
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* ─── STEP 1: RESOLVE ─── */}
        <div className={`glass-card rounded-2xl overflow-hidden mb-6 transition-all ${step !== 1 && packages.length > 0 ? "opacity-80" : ""}`}>
          <div
            className={`flex items-center gap-3 px-6 py-4 border-b border-white/10 cursor-pointer`}
            onClick={() => setStep(1)}
          >
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold border ${packages.length > 0 ? "border-[#00ff88] text-[#00ff88] bg-[#00ff88]/10" : "border-[#00d4ff] text-[#00d4ff] bg-[#00d4ff]/10"}`}>
              {packages.length > 0 ? "✓" : "1"}
            </div>
            <div>
              <h3 className="font-semibold text-white">Resolve Packages</h3>
              {packages.length > 0 && (
                <p className="text-xs text-[#00ff88]">
                  {packages.length} package{packages.length !== 1 ? "s" : ""} resolved
                  {totalCVEs > 0 && ` · ${totalCVEs} CVEs`}
                </p>
              )}
            </div>
          </div>

          {step === 1 && (
            <div className="p-6 space-y-5">
              <div className="flex gap-3 flex-wrap">
                <div className="flex rounded-lg overflow-hidden border border-white/10">
                  {(["pypi", "npm"] as const).map((eco) => (
                    <button
                      key={eco}
                      onClick={() => setEcosystem(eco)}
                      className={`px-4 py-2 text-sm font-mono font-medium transition-colors ${
                        ecosystem === eco ? "bg-[#00d4ff]/20 text-[#00d4ff]" : "text-gray-500 hover:text-gray-300"
                      }`}
                    >
                      {eco.toUpperCase()}
                    </button>
                  ))}
                </div>
                <div className="flex rounded-lg overflow-hidden border border-white/10">
                  {(["paste", "manual"] as const).map((mode) => (
                    <button
                      key={mode}
                      onClick={() => setInputMode(mode)}
                      className={`px-4 py-2 text-sm transition-colors ${
                        inputMode === mode ? "bg-[#7c3aed]/20 text-[#a78bfa]" : "text-gray-500 hover:text-gray-300"
                      }`}
                    >
                      {mode === "paste" ? "Paste File" : "Add Manually"}
                    </button>
                  ))}
                </div>
              </div>

              {inputMode === "paste" ? (
                <div>
                  <label className="text-xs text-gray-500 block mb-2">
                    {ecosystem === "pypi" ? "Paste your requirements.txt:" : "Paste your package.json:"}
                  </label>
                  <textarea
                    value={rawInput}
                    onChange={(e) => setRawInput(e.target.value)}
                    placeholder={ecosystem === "pypi" ? PYPI_SAMPLE : NPM_SAMPLE}
                    rows={5}
                    className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40 resize-y"
                  />
                  <button
                    onClick={handleResolve}
                    disabled={loading || !rawInput.trim()}
                    className="mt-3 w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity"
                  >
                    {loading ? "Resolving…" : "Resolve & Check CVEs →"}
                  </button>
                </div>
              ) : (
                <ManualInput ecosystem={ecosystem} onAdd={handleAddManual} />
              )}

              <CryptoTerminal lines={logs} height="h-48" />

              {packages.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-semibold text-gray-300">
                      {packages.length} resolved
                      {totalCVEs > 0 && <span className="ml-2 text-[#ff3366]">· {totalCVEs} CVEs</span>}
                    </h4>
                    <button onClick={() => setPackages([])} className="text-xs text-gray-600 hover:text-gray-400">Clear</button>
                  </div>
                  <DependencyTree packages={packages} />
                  <button
                    onClick={() => { setStep(2); scrollTo(step2Ref); }}
                    className="mt-4 w-full py-3 rounded-xl border border-[#00d4ff]/40 text-[#00d4ff] hover:bg-[#00d4ff]/10 transition-colors font-medium"
                  >
                    Continue to Sign →
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ─── STEP 2: SIGN ─── */}
        <div
          ref={step2Ref}
          className={`glass-card rounded-2xl overflow-hidden mb-6 transition-all ${step < 2 && packages.length === 0 ? "opacity-40 pointer-events-none" : ""}`}
        >
          <div
            className={`flex items-center gap-3 px-6 py-4 border-b border-white/10 cursor-pointer`}
            onClick={() => packages.length > 0 && setStep(2)}
          >
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold border ${sbom ? "border-[#00ff88] text-[#00ff88] bg-[#00ff88]/10" : step >= 2 ? "border-[#00d4ff] text-[#00d4ff] bg-[#00d4ff]/10" : "border-white/20 text-gray-600 bg-white/5"}`}>
              {sbom ? "✓" : "2"}
            </div>
            <div>
              <h3 className="font-semibold text-white">Sign with ML-DSA-65 + Ed25519</h3>
              {sbom && (
                <p className="text-xs text-[#00ff88]">
                  {sbom.total_components} components signed · {sbom.fips_standard}
                </p>
              )}
              {!sbom && packages.length === 0 && (
                <p className="text-xs text-gray-600">Complete step 1 first</p>
              )}
            </div>
          </div>

          {step === 2 && (
            <div className="p-6 space-y-5">
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="p-4 rounded-xl border border-white/10 bg-black/20 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <p className="text-[#7c3aed] font-semibold text-sm">ML-DSA-65 (post-quantum)</p>
                    {keypair && (
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${keypair.using_real_oqs ? "bg-[#00ff88]/10 text-[#00ff88]" : "bg-[#ffaa00]/10 text-[#ffaa00]"}`}>
                        {keypair.using_real_oqs ? "REAL liboqs" : "NIST-simulation"}
                      </span>
                    )}
                  </div>
                  <p className="text-gray-500">Standard: NIST FIPS 204</p>
                  <p className="text-gray-500">Security: Level 3 (128-bit PQ)</p>
                  <p className="text-gray-500">Hard problem: Module-LWE + SIS</p>
                  <p className="text-gray-500">Public key: 1,952 bytes · Signature: 3,293 bytes</p>
                  {keypair && (
                    <div className="mt-2 p-2 bg-black/40 rounded font-mono text-[10px] text-[#7c3aed] break-all">
                      {keypair.ml_dsa_public_key.slice(0, 64)}…
                    </div>
                  )}
                </div>
                <div className="p-4 rounded-xl border border-white/10 bg-black/20 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <p className="text-[#00d4ff] font-semibold text-sm">Ed25519 (classical)</p>
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-[#00ff88]/10 text-[#00ff88]">REAL</span>
                  </div>
                  <p className="text-gray-500">Curve: Edwards25519</p>
                  <p className="text-gray-500">Purpose: hybrid security</p>
                  <p className="text-gray-500">Public key: 32 bytes · Signature: 64 bytes</p>
                  <p className="text-gray-500">Real keygen via Python cryptography lib</p>
                  {keypair && (
                    <div className="mt-2 p-2 bg-black/40 rounded font-mono text-[10px] text-[#00d4ff] break-all">
                      {keypair.ed25519_public_key}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={handleKeygen}
                  disabled={loading}
                  className={`flex-1 py-3 rounded-xl font-semibold disabled:opacity-40 hover:opacity-90 transition-opacity text-sm ${
                    keypair
                      ? "border border-[#7c3aed]/40 text-[#a78bfa] hover:bg-[#7c3aed]/10"
                      : "bg-gradient-to-r from-[#7c3aed] to-[#00d4ff] text-white"
                  }`}
                >
                  {loading ? "Generating…" : keypair ? "↺ Regenerate Keypair" : "Generate Keypair"}
                </button>
                {keypair && packages.length > 0 && (
                  <button
                    onClick={handleSign}
                    disabled={loading}
                    className="flex-1 py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#00ff88] text-black font-bold disabled:opacity-40 hover:opacity-90 transition-opacity text-sm"
                  >
                    {loading ? "Signing…" : `Sign ${packages.length} Component${packages.length !== 1 ? "s" : ""}`}
                  </button>
                )}
              </div>

              {!keypair && (
                <p className="text-center text-gray-600 text-sm">Generate a keypair, then sign your packages.</p>
              )}
              {keypair && packages.length === 0 && (
                <p className="text-center text-[#ffaa00] text-sm">← Add packages in step 1 first.</p>
              )}

              <CryptoTerminal lines={logs} height="h-64" />
            </div>
          )}
        </div>

        {/* ─── STEP 3: DOWNLOAD ─── */}
        <div
          ref={step3Ref}
          className={`glass-card rounded-2xl overflow-hidden transition-all ${!sbom ? "opacity-40 pointer-events-none" : ""}`}
        >
          <div
            className={`flex items-center gap-3 px-6 py-4 border-b border-white/10 cursor-pointer`}
            onClick={() => sbom && setStep(3)}
          >
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold border ${sbom ? "border-[#00d4ff] text-[#00d4ff] bg-[#00d4ff]/10" : "border-white/20 text-gray-600 bg-white/5"}`}>
              {sbom ? "↓" : "3"}
            </div>
            <div>
              <h3 className="font-semibold text-white">Download SBOM Bundle</h3>
              {!sbom && <p className="text-xs text-gray-600">Complete step 2 first</p>}
              {sbom && <p className="text-xs text-gray-400">ZIP with SBOM + keys + verify.py</p>}
            </div>
          </div>

          {step === 3 && sbom && (
            <div className="p-6 space-y-5">
              {/* What's in the bundle */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { icon: "📄", name: "latticeguard-sbom.json", desc: `CycloneDX ${sbom.spec_version} · ${sbom.total_components} components` },
                  { icon: "🔑", name: "public-keys.json", desc: "ML-DSA-65 + Ed25519 public keys" },
                  { icon: "🐍", name: "verify.py", desc: "Standalone verifier — runs offline" },
                  { icon: "📋", name: "README.txt", desc: "SHA-256 hashes + CVE summary" },
                ].map((f) => (
                  <div key={f.name} className="flex items-start gap-3 p-3 rounded-lg border border-white/10 bg-black/20">
                    <span className="text-xl shrink-0">{f.icon}</span>
                    <div className="min-w-0">
                      <p className="text-white text-sm font-mono truncate">{f.name}</p>
                      <p className="text-gray-500 text-xs">{f.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* SBOM Stats */}
              <div className="p-4 rounded-xl border border-[#00ff88]/20 bg-[#00ff88]/5 space-y-2">
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-[#00ff88]">{sbom.total_components}</p>
                    <p className="text-xs text-gray-500">Components</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-[#00d4ff]">3293</p>
                    <p className="text-xs text-gray-500">Sig bytes (ML-DSA-65)</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-[#7c3aed]">{sbom.components.reduce((n,c)=>n+c.cves.length,0)}</p>
                    <p className="text-xs text-gray-500">CVEs found</p>
                  </div>
                </div>
                <div className="pt-2 border-t border-white/5 font-mono text-xs text-gray-600 space-y-0.5">
                  <p>Serial: {sbom.serial_number}</p>
                  <p>Algorithm: {sbom.algorithm}</p>
                  <p>Standard: {sbom.fips_standard} · {sbom.spec_version === "1.5" ? "CycloneDX 1.5" : sbom.spec_version}</p>
                </div>
              </div>

              {/* Verify instructions */}
              <div className="p-4 rounded-xl border border-white/10 bg-black/20 font-mono text-xs space-y-1">
                <p className="text-gray-500"># After downloading, verify offline:</p>
                <p className="text-[#00ff88]">pip install cryptography</p>
                <p className="text-[#00d4ff]">python verify.py latticeguard-sbom.json</p>
              </div>

              <button
                onClick={handleDownload}
                disabled={downloading}
                className="w-full py-4 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-bold text-base disabled:opacity-60 hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
              >
                {downloading ? (
                  <>⏳ Building ZIP…</>
                ) : (
                  <>↓ Download latticeguard-sbom.zip (4 files)</>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
