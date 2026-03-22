import { useState, useCallback, useRef } from "react";
import { manualLookup, ManualResult, Component, CVE } from "@/api/packages";

interface Props {
  ecosystem: string;
  onAdd: (component: Component, cves: CVE[]) => void;
}

export default function ManualInput({ ecosystem, onAdd }: Props) {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ManualResult | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lookup = useCallback(
    async (n: string, v: string) => {
      if (!n.trim()) {
        setResult(null);
        return;
      }
      setLoading(true);
      try {
        const [res] = await manualLookup([
          { name: n.trim(), version: v.trim() || undefined, ecosystem },
        ]);
        setResult(res);
      } catch {
        setResult({ status: "error", package: n, message: "Backend unavailable" });
      } finally {
        setLoading(false);
      }
    },
    [ecosystem]
  );

  const handleChange = (n: string, v: string) => {
    setName(n);
    setVersion(v);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => lookup(n, v), 600);
  };

  const handleAdd = () => {
    if (result?.status === "found" && result.component) {
      onAdd(result.component, result.cves ?? []);
      setName("");
      setVersion("");
      setResult(null);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <div className="flex-1">
          <label className="text-xs text-gray-500 mb-1 block">Package name</label>
          <input
            value={name}
            onChange={(e) => handleChange(e.target.value, version)}
            placeholder={ecosystem === "pypi" ? "e.g. requests" : "e.g. express"}
            className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00d4ff]/50"
          />
        </div>
        <div className="w-36">
          <label className="text-xs text-gray-500 mb-1 block">Version (optional)</label>
          <input
            value={version}
            onChange={(e) => handleChange(name, e.target.value)}
            placeholder="latest"
            className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00d4ff]/50"
          />
        </div>
      </div>

      {loading && (
        <div className="text-xs text-[#00d4ff] animate-pulse">Looking up {ecosystem} registry…</div>
      )}

      {result && !loading && (
        <div
          className={`rounded-lg p-3 text-sm border ${
            result.status === "found"
              ? "border-[#00ff88]/30 bg-[#00ff88]/5"
              : "border-[#ff3366]/30 bg-[#ff3366]/5"
          }`}
        >
          {result.status === "found" && result.component ? (
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-[#00ff88] font-mono font-semibold">
                  {result.component.name}@{result.component.version}
                </p>
                <p className="text-gray-400 text-xs mt-0.5 truncate">{result.component.description}</p>
                <p className="text-gray-500 text-xs mt-1">
                  License: {result.component.license} · {result.component.author}
                </p>
                {(result.cves?.length ?? 0) > 0 && (
                  <p className="text-[#ff3366] text-xs mt-1">
                    ⚠ {result.cves!.length} CVE{result.cves!.length !== 1 ? "s" : ""} found
                  </p>
                )}
              </div>
              <button
                onClick={handleAdd}
                className="shrink-0 px-3 py-1.5 bg-[#00d4ff]/20 hover:bg-[#00d4ff]/30 border border-[#00d4ff]/40 rounded text-[#00d4ff] text-xs font-medium transition-colors"
              >
                + Add
              </button>
            </div>
          ) : (
            <div>
              <p className="text-[#ff3366]">{result.message}</p>
              {result.available_versions && result.available_versions.length > 0 && (
                <div className="mt-2">
                  <p className="text-gray-400 text-xs mb-1">Available versions:</p>
                  <div className="flex flex-wrap gap-1">
                    {result.available_versions.map((v) => (
                      <button
                        key={v}
                        onClick={() => handleChange(name, v)}
                        className="px-2 py-0.5 text-xs bg-white/5 hover:bg-white/10 border border-white/10 rounded text-gray-300 font-mono transition-colors"
                      >
                        {v}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
