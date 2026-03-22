import { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import CryptoTerminal, { TerminalLine } from "@/components/CryptoTerminal";
import HexDiff from "@/components/HexDiff";
import { verifySBOM, simulateTamper, VerifyResult, TamperReport } from "@/api/verify";
import type { SBOM } from "@/api/signing";

export default function Verification() {
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [logs, setLogs] = useState<TerminalLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"idle" | "verified" | "tampered">("idle");
  const [results, setResults] = useState<VerifyResult[]>([]);
  const [tamperReport, setTamperReport] = useState<TamperReport | null>(null);
  const [fileName, setFileName] = useState("");

  const pushLog = useCallback(
    (text: string, type: TerminalLine["type"] = "info") => {
      setLogs((prev) => [...prev, { text, type }]);
    },
    []
  );

  const onDrop = useCallback((files: File[]) => {
    const file = files[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target?.result as string);
        setSbom(parsed);
        setMode("idle");
        setResults([]);
        setTamperReport(null);
        setLogs([]);
      } catch {
        setLogs([{ text: "Invalid JSON file.", type: "error" }]);
      }
    };
    reader.readAsText(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "application/json": [".json"] },
    multiple: false,
  });

  const handleVerify = async () => {
    if (!sbom) return;
    setLoading(true);
    setLogs([]);
    setMode("idle");
    setTamperReport(null);
    pushLog("Verifying SBOM integrity…", "info");
    pushLog(`Components to verify: ${sbom.components?.length ?? 0}`, "dim");

    try {
      const res = await verifySBOM(sbom);
      setResults(res.results);

      res.results.forEach((r) => {
        const icon = r.overall_valid ? "✓" : "✗";
        const type: TerminalLine["type"] = r.overall_valid ? "success" : "error";
        pushLog(
          `${icon} ${r.component}@${r.version} | hash:${r.hash_match ? "OK" : "FAIL"} ed25519:${r.ed25519_valid ? "OK" : "FAIL"} ml-dsa:${r.ml_dsa_valid ? "OK" : "FAIL"}`,
          type
        );
      });

      pushLog("", "dim");
      pushLog(
        `Result: ${res.passed}/${res.total} passed — ${res.status}`,
        res.overall_valid ? "success" : "error"
      );
      setMode(res.overall_valid ? "verified" : "tampered");
    } catch (e: unknown) {
      pushLog(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleTamperSim = async () => {
    if (!sbom) return;
    setLoading(true);
    setLogs([]);
    setMode("idle");
    setTamperReport(null);
    pushLog("Simulating supply chain attack…", "warn");
    pushLog("Injecting malicious payload into component metadata…", "warn");

    try {
      const report = await simulateTamper(sbom);
      setTamperReport(report);
      setResults(report.results);

      report.results.forEach((r) => {
        if (r.was_tampered) {
          pushLog(
            `⚠ TAMPERED: ${r.component}@${r.version} — hash mismatch detected!`,
            "error"
          );
        } else {
          pushLog(`✓ ${r.component}@${r.version} — clean`, "success");
        }
      });

      pushLog("", "dim");
      pushLog(`Attack type: ${report.attack_type}`, "error");
      pushLog(`Blocked by: ${report.blocked_by}`, "success");
      pushLog(`Status: ${report.status}`, "success");
      setMode("tampered");
    } catch (e: unknown) {
      pushLog(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const tamperedResult = tamperReport
    ? results.find((r) => r.was_tampered)
    : null;

  return (
    <section id="verify" className="py-20 px-4 bg-black/20">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-10">
          <h2 className="text-3xl font-bold mb-3">
            <span className="gradient-text">Verification Engine</span>
          </h2>
          <p className="text-gray-400 max-w-xl mx-auto">
            Upload any LatticeGuard SBOM and verify every ML-DSA-65 +
            Ed25519 signature. Simulate a supply chain attack to see tamper
            detection in action.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left: upload + controls */}
          <div className="space-y-4">
            <div
              {...getRootProps()}
              className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
                isDragActive
                  ? "border-[#00d4ff] bg-[#00d4ff]/5"
                  : sbom
                  ? "border-[#00ff88]/40 bg-[#00ff88]/5"
                  : "border-white/10 hover:border-white/20"
              }`}
            >
              <input {...getInputProps()} />
              {sbom ? (
                <div className="space-y-1">
                  <p className="text-[#00ff88] font-semibold">{fileName}</p>
                  <p className="text-gray-500 text-sm">
                    {sbom.components?.length ?? 0} components · {sbom.algorithm ?? "unknown algorithm"}
                  </p>
                  <p className="text-gray-600 text-xs">{sbom.serial_number}</p>
                  <p className="text-gray-600 text-xs mt-2">
                    Drop another file to replace
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-4xl text-gray-600">↑</div>
                  <p className="text-gray-400">
                    {isDragActive
                      ? "Drop SBOM here…"
                      : "Drop your SBOM JSON here"}
                  </p>
                  <p className="text-gray-600 text-sm">
                    or click to browse (.json)
                  </p>
                  <p className="text-gray-700 text-xs mt-2">
                    Generate one above using the SBOM tool
                  </p>
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={handleVerify}
                disabled={!sbom || loading}
                className="py-3 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity text-sm"
              >
                {loading ? "Verifying…" : "Verify Signatures"}
              </button>
              <button
                onClick={handleTamperSim}
                disabled={!sbom || loading}
                className="py-3 rounded-xl bg-gradient-to-r from-[#ff3366] to-[#7c3aed] text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-opacity text-sm"
              >
                {loading ? "Simulating…" : "Simulate Attack"}
              </button>
            </div>

            {mode !== "idle" && (
              <div
                className={`rounded-xl p-4 border text-center ${
                  mode === "verified"
                    ? "border-[#00ff88]/30 bg-[#00ff88]/5"
                    : "border-[#ff3366]/30 bg-[#ff3366]/5"
                }`}
              >
                <div className="text-3xl mb-2">
                  {mode === "verified" ? "✓" : "✗"}
                </div>
                <p
                  className={`font-bold text-lg ${
                    mode === "verified" ? "text-[#00ff88]" : "text-[#ff3366]"
                  }`}
                >
                  {mode === "verified"
                    ? "SAFE TO INSTALL"
                    : tamperReport
                    ? "ATTACK DETECTED & BLOCKED"
                    : "VERIFICATION FAILED"}
                </p>
                {tamperReport && (
                  <div className="mt-2 text-xs text-gray-500 space-y-0.5">
                    <p>Tampered: {tamperReport.tampered_component}</p>
                    <p>Attack: {tamperReport.attack_type}</p>
                    <p>Blocked by: {tamperReport.blocked_by}</p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right: terminal + hex diff */}
          <div className="space-y-4">
            <CryptoTerminal lines={logs} height="h-72" />

            {tamperedResult && (
              <HexDiff
                original={tamperedResult.recomputed_hash ?? "0".repeat(64)}
                tampered={tamperedResult.stored_hash ?? "f".repeat(64)}
                label={`Tamper Detected: ${tamperedResult.component}`}
              />
            )}

            {results.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs text-gray-600 uppercase tracking-wider mb-2">
                  Verification Results
                </p>
                {results.map((r, i) => (
                  <div
                    key={i}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
                      r.overall_valid
                        ? "bg-[#00ff88]/5 text-[#00ff88]"
                        : "bg-[#ff3366]/5 text-[#ff3366]"
                    }`}
                  >
                    <span>{r.overall_valid ? "✓" : "✗"}</span>
                    <span className="font-mono flex-1">
                      {r.component}@{r.version}
                    </span>
                    {r.was_tampered && (
                      <span className="text-[#ff3366] font-semibold">
                        TAMPERED
                      </span>
                    )}
                    <span className="text-gray-600 ml-auto">
                      h:{r.hash_match ? "✓" : "✗"} e:{r.ed25519_valid ? "✓" : "✗"} q:{r.ml_dsa_valid ? "✓" : "✗"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
