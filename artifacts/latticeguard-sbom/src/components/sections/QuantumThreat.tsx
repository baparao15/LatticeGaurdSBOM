import { motion } from "framer-motion";
import { Zap, AlertTriangle, ShieldCheck, Clock } from "lucide-react";

const ALGORITHMS = [
  {
    name: "RSA-2048",
    type: "Classical",
    typeColor: "#ff3366",
    quantumThreat: "BROKEN",
    threatColor: "#ff3366",
    attack: "Shor's Algorithm",
    qubits: "~4,000",
    keySize: "256 B",
    sigSize: "256 B",
    problem: "Integer Factorisation",
    nistrevel: null,
  },
  {
    name: "ECDSA-256",
    type: "Classical",
    typeColor: "#ff3366",
    quantumThreat: "BROKEN",
    threatColor: "#ff3366",
    attack: "Shor's Algorithm",
    qubits: "~2,500",
    keySize: "32 B",
    sigSize: "64 B",
    problem: "Elliptic Curve DLog",
    nistrevel: null,
  },
  {
    name: "SHA-256 HMAC",
    type: "Classical",
    typeColor: "#ff9900",
    quantumThreat: "WEAKENED",
    threatColor: "#ff9900",
    attack: "Grover's Algorithm (128-bit security)",
    qubits: "Millions",
    keySize: "32 B",
    sigSize: "32 B",
    problem: "Hash Preimage",
    nistrevel: null,
  },
  {
    name: "ML-DSA-65",
    type: "Post-Quantum",
    typeColor: "#00ff88",
    quantumThreat: "SAFE",
    threatColor: "#00ff88",
    attack: "None known",
    qubits: "∞",
    keySize: "1,952 B",
    sigSize: "3,293 B",
    problem: "Module-LWE + Module-SIS",
    nistrevel: "Level 3",
  },
  {
    name: "ML-KEM-768",
    type: "Post-Quantum",
    typeColor: "#00ff88",
    quantumThreat: "SAFE",
    threatColor: "#00ff88",
    attack: "None known",
    qubits: "∞",
    keySize: "1,184 B",
    sigSize: "N/A (KEM)",
    problem: "Module-LWE",
    nistrevel: "Level 3",
  },
];

const TIMELINE = [
  { year: "2019", event: "Google achieves quantum supremacy (53 qubits)", risk: "low" },
  { year: "2022", event: "IBM Eagle reaches 127 qubits", risk: "low" },
  { year: "2024", event: "NIST finalises FIPS 203, 204, 205 (PQC standards)", risk: "medium" },
  { year: "~2030", event: "Cryptographically relevant quantum computer (CRQC) possible", risk: "high" },
  { year: "~2035", event: "RSA-2048 / ECDSA-256 may be broken by quantum adversaries", risk: "critical" },
];

export default function QuantumThreat() {
  return (
    <section id="threat" className="py-20 px-4 relative">
      <div className="absolute inset-0 lattice-bg opacity-20" />

      <div className="max-w-5xl mx-auto space-y-10 relative">
        {/* Header */}
        <div className="text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#ff3366]/10 border border-[#ff3366]/20 mb-4">
            <AlertTriangle className="w-3.5 h-3.5 text-[#ff3366]" />
            <span className="text-xs text-[#ff3366] font-medium">Phase 5 — Quantum Threat Simulator</span>
          </div>
          <h2 className="text-3xl font-bold text-white mb-3">
            The <span className="text-[#ff3366]">Quantum Threat</span> to Your Supply Chain
          </h2>
          <p className="text-gray-400 text-sm max-w-xl mx-auto">
            Shor's algorithm breaks RSA and ECDSA on a cryptographically relevant quantum computer.
            LatticeGuard's ML-DSA-65 signatures are designed to resist both classical and quantum adversaries.
          </p>
        </div>

        {/* Algorithm comparison table */}
        <div className="glass-card rounded-2xl overflow-hidden">
          <div className="px-5 py-4 border-b border-white/10 flex items-center gap-2">
            <Zap className="w-4 h-4 text-[#ff9900]" />
            <span className="text-sm font-semibold text-white">Algorithm Threat Assessment</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/5 text-xs text-gray-500 font-mono">
                  <th className="text-left px-5 py-3">Algorithm</th>
                  <th className="text-left px-3 py-3">Hard Problem</th>
                  <th className="text-left px-3 py-3">Quantum Attack</th>
                  <th className="text-center px-3 py-3">Qubits Needed</th>
                  <th className="text-center px-3 py-3">Pub Key</th>
                  <th className="text-center px-3 py-3">Sig Size</th>
                  <th className="text-center px-3 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {ALGORITHMS.map((alg) => (
                  <tr key={alg.name} className="text-xs hover:bg-white/2 transition-colors">
                    <td className="px-5 py-3">
                      <div className="font-bold text-white font-mono">{alg.name}</div>
                      <div
                        className="text-[10px] font-mono mt-0.5"
                        style={{ color: alg.typeColor }}
                      >
                        {alg.type}
                        {alg.nistrevel && ` · NIST ${alg.nistrevel}`}
                      </div>
                    </td>
                    <td className="px-3 py-3 text-gray-400 font-mono text-[11px]">
                      {alg.problem}
                    </td>
                    <td className="px-3 py-3 text-gray-400 font-mono text-[11px]">
                      {alg.attack}
                    </td>
                    <td className="px-3 py-3 text-center font-mono" style={{ color: alg.threatColor }}>
                      {alg.qubits}
                    </td>
                    <td className="px-3 py-3 text-center text-gray-400 font-mono">{alg.keySize}</td>
                    <td className="px-3 py-3 text-center text-gray-400 font-mono">{alg.sigSize}</td>
                    <td className="px-3 py-3 text-center">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold"
                        style={{
                          backgroundColor: `${alg.threatColor}15`,
                          color: alg.threatColor,
                          border: `1px solid ${alg.threatColor}30`,
                        }}
                      >
                        {alg.quantumThreat}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Two-column: Lattice viz + timeline */}
        <div className="grid md:grid-cols-2 gap-6">
          {/* Lattice visualization */}
          <div className="glass-card rounded-2xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <ShieldCheck className="w-4 h-4 text-[#7c3aed]" />
              <span className="text-sm font-semibold text-white">Module-LWE Lattice Basis</span>
            </div>
            <p className="text-xs text-gray-500 mb-4">
              ML-DSA-65 security rests on the hardness of finding the shortest vector in a
              high-dimensional lattice — a problem believed intractable even for quantum computers.
            </p>
            <LatticeViz />
            <p className="text-[10px] text-gray-600 mt-3 text-center font-mono">
              2D projection of Module-LWE lattice · dim=256 in practice
            </p>
          </div>

          {/* Quantum timeline */}
          <div className="glass-card rounded-2xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Clock className="w-4 h-4 text-[#ff9900]" />
              <span className="text-sm font-semibold text-white">Quantum Computing Timeline</span>
            </div>
            <div className="space-y-3">
              {TIMELINE.map((t, i) => {
                const riskColor =
                  t.risk === "critical"
                    ? "#ff3366"
                    : t.risk === "high"
                    ? "#ff9900"
                    : t.risk === "medium"
                    ? "#a78bfa"
                    : "#00d4ff";
                return (
                  <motion.div
                    key={t.year}
                    initial={{ opacity: 0, x: 20 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.1 }}
                    className="flex items-start gap-3"
                  >
                    <div
                      className="flex-shrink-0 w-14 text-right font-mono text-xs font-bold"
                      style={{ color: riskColor }}
                    >
                      {t.year}
                    </div>
                    <div
                      className="flex-shrink-0 w-2 h-2 rounded-full mt-1"
                      style={{ backgroundColor: riskColor }}
                    />
                    <p className="text-xs text-gray-400 leading-relaxed">{t.event}</p>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Grover vs Shor callout */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="glass-card rounded-xl p-4 border border-[#ff3366]/20">
            <h4 className="text-sm font-bold text-[#ff3366] mb-2">Shor's Algorithm</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Runs in polynomial time O(log³ N) on a quantum computer and factors integers or
              computes discrete logarithms. Directly breaks RSA-2048 and all ECDSA/DH variants.
              A 4,000-logical-qubit CRQC could break RSA-2048 in hours.
            </p>
          </div>
          <div className="glass-card rounded-xl p-4 border border-[#ff9900]/20">
            <h4 className="text-sm font-bold text-[#ff9900] mb-2">Grover's Algorithm</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Provides a quadratic speedup for brute-force search. Effectively halves symmetric key
              and hash security levels: SHA-256 drops from 256-bit to ~128-bit against a quantum
              adversary. Mitigated by doubling key sizes (AES-256, SHA-384+).
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function LatticeViz() {
  const COLS = 9;
  const ROWS = 7;
  const pts = [];

  for (let i = 0; i < COLS; i++) {
    for (let j = 0; j < ROWS; j++) {
      const jitter = (Math.sin(i * 3 + j * 7) * 4);
      pts.push({ x: 16 + i * 24 + jitter, y: 14 + j * 20, i, j });
    }
  }

  const shortVecs = [
    { from: { x: 16 + 4 * 24, y: 14 + 3 * 20 }, to: { x: 16 + 5 * 24, y: 14 + 3 * 20 } },
    { from: { x: 16 + 4 * 24, y: 14 + 3 * 20 }, to: { x: 16 + 4 * 24, y: 14 + 2 * 20 } },
  ];

  return (
    <svg viewBox="0 0 228 148" className="w-full border border-[#7c3aed]/20 rounded-lg bg-black/30">
      {/* Grid points */}
      {pts.map((p, k) => (
        <motion.circle
          key={k}
          cx={p.x}
          cy={p.y}
          r={2}
          fill="#7c3aed"
          opacity={0.5}
          animate={{ opacity: [0.3, 0.7, 0.3] }}
          transition={{ duration: 2.5, repeat: Infinity, delay: (p.i + p.j) * 0.1 }}
        />
      ))}

      {/* Basis vectors */}
      <line x1="16" y1={14 + 3 * 20} x2={16 + 2 * 24} y2={14 + 3 * 20} stroke="#00d4ff" strokeWidth="1.5" markerEnd="url(#arrow)" opacity="0.7" />
      <line x1="16" y1={14 + 3 * 20} x2="16" y2={14 + 1 * 20} stroke="#00d4ff" strokeWidth="1.5" opacity="0.7" />

      {/* Shortest vectors */}
      {shortVecs.map((v, k) => (
        <motion.line
          key={k}
          x1={v.from.x}
          y1={v.from.y}
          x2={v.to.x}
          y2={v.to.y}
          stroke="#00ff88"
          strokeWidth="2"
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 2, repeat: Infinity, delay: k * 0.5 }}
        />
      ))}

      {/* Labels */}
      <text x="6" y={14 + 3 * 20 - 4} fill="#00d4ff" fontSize="7" fontFamily="monospace">b₁</text>
      <text x={16 + 2 * 24 + 2} y={14 + 3 * 20 + 3} fill="#00d4ff" fontSize="7" fontFamily="monospace">b₂</text>
      <text x={16 + 4 * 24 + 4} y={14 + 3 * 20 - 4} fill="#00ff88" fontSize="7" fontFamily="monospace">SVP</text>
    </svg>
  );
}
