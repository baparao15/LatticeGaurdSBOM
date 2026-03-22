import type { ResolvedPackage } from "@/api/packages";

interface Props {
  packages: ResolvedPackage[];
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-[#ff3366] bg-[#ff3366]/10",
  HIGH: "text-orange-400 bg-orange-400/10",
  MEDIUM: "text-yellow-400 bg-yellow-400/10",
  LOW: "text-gray-400 bg-white/5",
  UNKNOWN: "text-gray-500 bg-white/5",
};

export default function DependencyTree({ packages }: Props) {
  if (packages.length === 0) return null;

  return (
    <div className="space-y-2">
      {packages.map((pkg, i) => (
        <div
          key={`${pkg.component.name}-${i}`}
          className="border border-white/10 rounded-lg overflow-hidden"
        >
          <div className="flex items-start gap-3 p-3 bg-white/[0.02] hover:bg-white/[0.04] transition-colors">
            <div className="shrink-0 w-5 h-5 rounded-full bg-[#00d4ff]/20 flex items-center justify-center mt-0.5">
              <div className="w-2 h-2 rounded-full bg-[#00d4ff]" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-white font-medium">
                  {pkg.component.name}
                </span>
                <span className="font-mono text-[#00d4ff] text-sm">
                  @{pkg.component.version}
                </span>
                <span className="text-gray-600 text-xs uppercase">
                  {pkg.component.ecosystem}
                </span>
                {pkg.cves.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-xs font-medium text-[#ff3366] bg-[#ff3366]/10">
                    {pkg.cves.length} CVE{pkg.cves.length !== 1 ? "s" : ""}
                  </span>
                )}
              </div>
              <p className="text-gray-500 text-xs mt-0.5 truncate">{pkg.component.description}</p>
              <div className="flex items-center gap-3 mt-1 text-xs text-gray-600">
                <span>{pkg.component.license}</span>
                {pkg.component.size_bytes > 0 && (
                  <span>{(pkg.component.size_bytes / 1024).toFixed(1)} KB</span>
                )}
                {pkg.transitive_count > 0 && (
                  <span className="text-[#7c3aed]">
                    +{pkg.transitive_count} transitive
                  </span>
                )}
              </div>
            </div>
          </div>

          {pkg.cves.length > 0 && (
            <div className="border-t border-white/5 px-3 py-2 space-y-1">
              {pkg.cves.map((cve) => (
                <div
                  key={cve.id}
                  className="flex items-start gap-2 text-xs"
                >
                  <span
                    className={`shrink-0 px-1.5 py-0.5 rounded font-mono font-medium ${
                      SEVERITY_COLORS[cve.severity] ?? SEVERITY_COLORS.UNKNOWN
                    }`}
                  >
                    {cve.severity}
                  </span>
                  <span className="text-gray-400">{cve.id}</span>
                  <span className="text-gray-600 truncate">{cve.summary}</span>
                  {cve.fixed_in && (
                    <span className="shrink-0 text-[#00ff88]">
                      fix: {cve.fixed_in}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}

          {pkg.component.dependencies.length > 0 && (
            <div className="border-t border-white/5 px-3 py-2">
              <p className="text-xs text-gray-600 mb-1">Direct dependencies:</p>
              <div className="flex flex-wrap gap-1">
                {pkg.component.dependencies.slice(0, 12).map((dep) => (
                  <span
                    key={dep}
                    className="px-1.5 py-0.5 rounded text-xs font-mono bg-[#7c3aed]/10 text-[#a78bfa] border border-[#7c3aed]/20"
                  >
                    {dep}
                  </span>
                ))}
                {pkg.component.dependencies.length > 12 && (
                  <span className="text-xs text-gray-600">
                    +{pkg.component.dependencies.length - 12} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
