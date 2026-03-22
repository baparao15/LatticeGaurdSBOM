import { useState, useCallback } from "react";
import CryptoTerminal, { TerminalLine } from "@/components/CryptoTerminal";
import ManualInput from "@/components/ManualInput";
import DependencyTree from "@/components/DependencyTree";
import { resolveDependencies, ResolvedPackage, Component, CVE } from "@/api/packages";
import { generateKeypair, signAllComponents, SBOM, KeygenResult } from "@/api/signing";

type Tab = "generate" | "sign" | "export";

const PYPI_SAMPLE = `requests==2.31.0
cryptography==42.0.0
fastapi==0.100.0`;

const NPM_SAMPLE = `{
  "dependencies": {
    "express": "^4.18.2",
    "axios": "^1.6.0"
  }
}`;

export default function MainTool() {
  const [tab, setTab] = useState<Tab>("generate");
  const [ecosystem, setEcosystem] = useState<"pypi" | "npm">("pypi");
  const [inputMode, setInputMode] = useState<"paste" | "manual">("paste");
  const [rawInput, setRawInput] = useState("");
  const [packages, setPackages] = useState<ResolvedPackage[]>([]);
  const [keypair, setKeypair] = useState<KeygenResult | null>(null);
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [logs, setLogs] = useState<TerminalLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  const pushLog = useCallback(
    (text: string, type: TerminalLine["type"] = "info") => {
      setLogs((prev) => [...prev, { text, type }]);
    },
    []
  );

  const clearLogs = () => setLogs([]);

  const checkBackend = async () => {
    try {
      const res = await fetch("/latticeguard-api/health");
      if (res.ok) {
        const data = await res.json();
        setBackendOnline(true);
        return data;
      }
    } catch {
      setBackendOnline(false);
    }
    return null;
  };

  const handleResolve = async () => {
    const input = rawInput.trim();
    if (!input) return;
    setLoading(true);
    clearLogs();
    pushLog("Connecting to LatticeGuard backend…", "dim");

    const health = await checkBackend();
    if (!health) {
      pushLog("❌ Backend offline. Start the Python server workflow.", "error");
      setLoading(false);
      return;
    }
    pushLog(
      `✓ Backend: ${health.status} | OQS: ${health.real_oqs ? "REAL liboqs" : "high-fidelity simulation"}`,
      "success"
    );
    pushLog(`Resolving ${ecosystem.toUpperCase()} dependencies…`, "info");

    try {
      const result = await resolveDependencies(input, ecosystem);
      result.components.forEach((pkg) => {
        const cveStr = pkg.cves.length ? ` [${pkg.cves.length} CVEs]` : "";
        pushLog(
          `✓ ${pkg.component.name}@${pkg.component.version}${cveStr} (+${pkg.transitive_count} transitive)`,
          pkg.cves.length > 0 ? "warn" : "success"
        );
      });
      result.errors.forEach((err) => {
        pushLog(`✗ ${err.package}: ${err.error}`, "error");
      });
      pushLog(
        `Done: ${result.total_found} resolved, ${result.total_failed} failed.`,
        "dim"
      );
      setPackages(result.components);
    } catch (e: unknown) {
      pushLog(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleAddManual = (component: Component, cves: CVE[]) => {
    const exists = packages.find(
      (p) =>
        p.component.name === component.name &&
        p.component.version === component.version
    );
    if (!exists) {
      setPackages((prev) => [
        ...prev,
        { component, cves, transitive_count: 0, transitive: [] },
      ]);
      pushLog(`+ Added ${component.name}@${component.version}`, "success");
    }
  };

  const handleKeygen = async () => {
    setLoading(true);
    clearLogs();
    pushLog("Generating ML-DSA-65 keypair (NIST FIPS 204)…", "info");

    const health = await checkBackend();
    if (!health) {
      pushLog("❌ Backend offline. Start the Python server workflow.", "error");
      setLoading(false);
      return;
    }

    try {
      const kp = await generateKeypair();
      setKeypair(kp);
      pushLog(`✓ ${kp.message}`, "success");
      pushLog(`  Algorithm: ${kp.algorithm} | Standard: ${kp.fips_standard}`, "dim");
      pushLog(`  Security level: ${kp.security_level}`, "dim");
      pushLog(
        `  ML-DSA-65 public key (${kp.ml_dsa_public_key_size} bytes): ${kp.ml_dsa_public_key.slice(0, 32)}…`,
        "dim"
      );
      pushLog(
        `  Ed25519 public key (32 bytes): ${kp.ed25519_public_key.slice(0, 32)}…`,
        "dim"
      );
      pushLog(`  Hard problem: Module-LWE + Module-SIS`, "dim");
      pushLog(`  Quantum-safe: YES ✓`, "success");
      setTab("sign");
    } catch (e: unknown) {
      pushLog(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleSign = async () => {
    if (!keypair) {
      pushLog("Generate a keypair first!", "error");
      return;
    }
    if (packages.length === 0) {
      pushLog("Add packages first (Resolve tab).", "error");
      return;
    }
    setLoading(true);
    clearLogs();
    pushLog(`Signing ${packages.length} component(s) with ML-DSA-65…`, "info");

    try {
      const result = await signAllComponents(packages);
      setSbom(result);
      result.components.forEach((sc) => {
        pushLog(
          `✓ Signed ${sc.component.name}@${sc.component.version} | sig: ${sc.signature_size_bytes} bytes`,
          "success"
        );
        pushLog(`  sha256: ${sc.sha256_signed.slice(0, 32)}…`, "dim");
      });
      pushLog(``, "dim");
      pushLog(`SBOM serial: ${result.serial_number}`, "dim");
      pushLog(
        `Quantum-safe: ${result.quantum_safe ? "YES ✓" : "NO"}`,
        result.quantum_safe ? "success" : "error"
      );
      pushLog(
        `All ${result.total_components} components signed successfully.`,
        "success"
      );
      setTab("export");
    } catch (e: unknown) {
      pushLog(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    if (!sbom) return;
    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `latticeguard-sbom-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: "generate", label: "1. Resolve", icon: "⬡" },
    { id: "sign", label: "2. Sign", icon: "⊕" },
    { id: "export", label: "3. Export", icon: "↓" },
  ];

  const totalCVEs = packages.reduce((acc, p) => acc + p.cves.length, 0);

  return (
    <section id="tool" className="py-20 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-10">
          <h2 className="text-3xl font-bold mb-3">
            <span className="gradient-text">SBOM Generator</span>
          </h2>
          <p className="text-gray-400 max-w-xl mx-auto">
            Resolve real package metadata from PyPI/npm, check CVEs via OSV
            API, then sign every component with hybrid ML-DSA-65 + Ed25519.
          </p>
          {backendOnline === false && (
            <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#ff3366]/10 border border-[#ff3366]/30 text-[#ff3366] text-sm">
              ⚠ Backend offline — start the "LatticeGuard Python Backend" workflow
            </div>
          )}
          {backendOnline === true && (
            <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] text-sm">
              ✓ Backend connected
            </div>
          )}
        </div>

        <div className="glass-card rounded-2xl overflow-hidden">
          {/* Tab bar */}
          <div className="flex border-b border-white/10">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex-1 flex items-center justify-center gap-2 py-4 text-sm font-medium transition-all ${
                  tab === t.id
                    ? "text-[#00d4ff] border-b-2 border-[#00d4ff] bg-[#00d4ff]/5"
                    : "text-gray-500 hover:text-gray-300"
                }`}
              >
                <span>{t.icon}</span>
                {t.label}
              </button>
            ))}
          </div>

          <div className="p-6 space-y-6">
            {/* ── GENERATE TAB ── */}
            {tab === "generate" && (
              <div className="space-y-5">
                <div className="flex gap-3 items-center flex-wrap">
                  <div className="flex rounded-lg overflow-hidden border border-white/10">
                    {(["pypi", "npm"] as const).map((eco) => (
                      <button
                        key={eco}
                        onClick={() => setEcosystem(eco)}
                        className={`px-4 py-2 text-sm font-mono font-medium transition-colors ${
                          ecosystem === eco
                            ? "bg-[#00d4ff]/20 text-[#00d4ff]"
                            : "text-gray-500 hover:text-gray-300"
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
                        className={`px-4 py-2 text-sm transition-colors capitalize ${
                          inputMode === mode
                            ? "bg-[#7c3aed]/20 text-[#a78bfa]"
                            : "text-gray-500 hover:text-gray-300"
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
                      {ecosystem === "pypi"
                        ? "Paste requirements.txt or import lines"
                        : "Paste package.json or package names"}
                    </label>
                    <textarea
                      value={rawInput}
                      onChange={(e) => setRawInput(e.target.value)}
                      placeholder={
                        ecosystem === "pypi" ? PYPI_SAMPLE : NPM_SAMPLE
                      }
                      rows={6}
                      className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-gray-700 focus:outline-none focus:border-[#00d4ff]/40 resize-y"
                    />
                    <button
                      onClick={handleResolve}
                      disabled={loading || !rawInput.trim()}
                      className="mt-3 w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-opacity hover:opacity-90"
                    >
                      {loading ? "Resolving…" : "Resolve & Check CVEs"}
                    </button>
                  </div>
                ) : (
                  <ManualInput ecosystem={ecosystem} onAdd={handleAddManual} />
                )}

                <CryptoTerminal lines={logs} height="h-48" />

                {packages.length > 0 && (
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-gray-300">
                        {packages.length} component
                        {packages.length !== 1 ? "s" : ""} resolved
                        {totalCVEs > 0 && (
                          <span className="ml-2 text-[#ff3366]">
                            · {totalCVEs} CVE{totalCVEs !== 1 ? "s" : ""}
                          </span>
                        )}
                      </h3>
                      <button
                        onClick={() => setPackages([])}
                        className="text-xs text-gray-600 hover:text-gray-400"
                      >
                        Clear all
                      </button>
                    </div>
                    <DependencyTree packages={packages} />
                    <button
                      onClick={() => setTab("sign")}
                      className="mt-4 w-full py-3 rounded-xl border border-[#7c3aed]/50 text-[#a78bfa] hover:bg-[#7c3aed]/10 transition-colors font-medium"
                    >
                      Continue to Sign →
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* ── SIGN TAB ── */}
            {tab === "sign" && (
              <div className="space-y-5">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl border border-white/10 bg-black/20 space-y-2">
                    <h3 className="text-sm font-semibold text-gray-300">
                      ML-DSA-65 (FIPS 204)
                    </h3>
                    <div className="space-y-1 text-xs text-gray-500">
                      <p>Hard problem: Module-LWE + Module-SIS</p>
                      <p>Security: NIST Level 3</p>
                      <p>Public key: 1952 bytes</p>
                      <p>Signature: 3293 bytes</p>
                    </div>
                    {keypair && (
                      <div className="mt-2 p-2 bg-black/40 rounded font-mono text-[10px] text-[#00d4ff] break-all">
                        {keypair.ml_dsa_public_key.slice(0, 48)}…
                      </div>
                    )}
                  </div>
                  <div className="p-4 rounded-xl border border-white/10 bg-black/20 space-y-2">
                    <h3 className="text-sm font-semibold text-gray-300">
                      Ed25519 (classical hybrid)
                    </h3>
                    <div className="space-y-1 text-xs text-gray-500">
                      <p>Curve: Edwards25519</p>
                      <p>Public key: 32 bytes</p>
                      <p>Signature: 64 bytes</p>
                      <p>Purpose: classical security fallback</p>
                    </div>
                    {keypair && (
                      <div className="mt-2 p-2 bg-black/40 rounded font-mono text-[10px] text-[#7c3aed] break-all">
                        {keypair.ed25519_public_key}
                      </div>
                    )}
                  </div>
                </div>

                <button
                  onClick={handleKeygen}
                  disabled={loading}
                  className="w-full py-3 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#00d4ff] text-white font-semibold disabled:opacity-40 transition-opacity hover:opacity-90"
                >
                  {loading
                    ? "Generating…"
                    : keypair
                    ? "Regenerate Keypair"
                    : "Generate ML-DSA-65 Keypair"}
                </button>

                {keypair && packages.length > 0 && (
                  <button
                    onClick={handleSign}
                    disabled={loading}
                    className="w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#00ff88] text-black font-bold disabled:opacity-40 transition-opacity hover:opacity-90"
                  >
                    {loading
                      ? "Signing…"
                      : `Sign ${packages.length} Component${
                          packages.length !== 1 ? "s" : ""
                        }`}
                  </button>
                )}

                {!keypair && (
                  <p className="text-center text-gray-600 text-sm">
                    Generate a keypair first, then sign your resolved
                    components.
                  </p>
                )}
                {keypair && packages.length === 0 && (
                  <p className="text-center text-[#ffaa00] text-sm">
                    ← Resolve some packages first (step 1).
                  </p>
                )}

                <CryptoTerminal lines={logs} height="h-64" />
              </div>
            )}

            {/* ── EXPORT TAB ── */}
            {tab === "export" && (
              <div className="space-y-5">
                {sbom ? (
                  <>
                    <div className="p-4 rounded-xl border border-[#00ff88]/30 bg-[#00ff88]/5">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-8 h-8 rounded-full bg-[#00ff88]/20 flex items-center justify-center text-[#00ff88]">
                          ✓
                        </div>
                        <div>
                          <p className="text-[#00ff88] font-semibold">
                            SBOM Ready
                          </p>
                          <p className="text-gray-500 text-xs">
                            {sbom.total_components} components · CycloneDX{" "}
                            {sbom.spec_version} · {sbom.algorithm}
                          </p>
                        </div>
                      </div>
                      <div className="font-mono text-xs text-gray-500 space-y-0.5">
                        <p>Serial: {sbom.serial_number}</p>
                        <p>
                          Generated:{" "}
                          {new Date(
                            parseFloat(sbom.generated_at) * 1000
                          ).toISOString()}
                        </p>
                        <p>Tool: {sbom.tool}</p>
                      </div>
                    </div>

                    <div className="bg-black/60 rounded-xl p-4 font-mono text-xs text-gray-400 max-h-60 overflow-auto border border-white/5">
                      {JSON.stringify(sbom, null, 2).slice(0, 2000)}…
                    </div>

                    <button
                      onClick={handleExport}
                      className="w-full py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold hover:opacity-90 transition-opacity"
                    >
                      ↓ Download latticeguard-sbom.json
                    </button>
                  </>
                ) : (
                  <div className="text-center py-12">
                    <p className="text-gray-600">
                      Complete steps 1 and 2 to generate your signed SBOM.
                    </p>
                    <button
                      onClick={() => setTab("generate")}
                      className="mt-4 px-6 py-2 rounded-lg border border-white/10 text-gray-400 hover:text-white transition-colors text-sm"
                    >
                      ← Start over
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
