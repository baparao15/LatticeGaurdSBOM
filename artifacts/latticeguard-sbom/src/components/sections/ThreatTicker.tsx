import { AlertTriangle } from "lucide-react";

const threats = [
  "⚠ HNDL Attack Detected on US Treasury — 2024",
  "⚠ SolarWinds Supply Chain Breach — 18,000 orgs affected",
  "⚠ Quantum Computer milestone: 1000+ qubits achieved — IBM",
  "⚠ CISA mandates PQC migration for all federal agencies by 2030",
  "⚠ RSA-2048 estimated breakable in ~10 years by CRQC",
  "⚠ Software dependency attacks rose 650% in 2023"
];

export default function ThreatTicker() {
  return (
    <div className="w-full bg-gradient-to-r from-destructive/80 to-warning/80 border-y border-destructive/50 overflow-hidden relative z-20 shadow-[0_0_20px_rgba(255,51,102,0.2)]">
      <div className="flex whitespace-nowrap py-3 items-center">
        <div className="animate-marquee flex space-x-12 shrink-0 pr-12">
          {threats.map((threat, i) => (
            <span key={i} className="text-sm font-mono font-bold text-white tracking-widest uppercase flex items-center">
              {threat}
            </span>
          ))}
          {/* Duplicate for infinite loop */}
          {threats.map((threat, i) => (
            <span key={`dup-${i}`} className="text-sm font-mono font-bold text-white tracking-widest uppercase flex items-center">
              {threat}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
