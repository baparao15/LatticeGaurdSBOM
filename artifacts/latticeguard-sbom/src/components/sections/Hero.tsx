import { motion } from "framer-motion";
import { Shield, ShieldCheck, Zap, Lock, ArrowRight } from "lucide-react";

const STATS = [
  { value: "8,000+", label: "Packages tracked", color: "#00d4ff" },
  { value: "5-signal", label: "Risk score engine", color: "#7c3aed" },
  { value: "ML-DSA-65", label: "NIST FIPS 204", color: "#00ff88" },
  { value: "3,293 B", label: "Sig size (PQ)", color: "#ff9900" },
];

export default function Hero() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center pt-16 overflow-hidden">
      {/* Animated lattice grid */}
      <div className="absolute inset-0 lattice-bg animate-lattice opacity-60" />

      {/* Radial glows */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-[#7c3aed]/8 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute top-1/3 left-1/4 w-[400px] h-[400px] bg-[#00d4ff]/5 rounded-full blur-[80px] pointer-events-none" />

      {/* Lattice nodes + connecting lines */}
      <LatticeNodes />

      {/* Content */}
      <div className="relative z-10 max-w-5xl mx-auto px-4 text-center">

        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#7c3aed]/10 border border-[#7c3aed]/30 mb-8"
        >
          <Zap className="w-3.5 h-3.5 text-[#a78bfa]" />
          <span className="text-sm text-[#a78bfa] font-medium">
            Post-Quantum Cryptography · NIST FIPS 204 ML-DSA-65
          </span>
          <ShieldCheck className="w-3.5 h-3.5 text-[#00ff88]" />
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="text-5xl md:text-7xl font-bold leading-tight mb-6"
        >
          <span className="text-white">Quantum-Safe</span>
          <br />
          <span className="gradient-text">Supply Chain Security</span>
        </motion.h1>

        {/* Sub */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-lg md:text-xl text-gray-400 max-w-3xl mx-auto mb-10 leading-relaxed"
        >
          Verify package names against 8,000 top PyPI packages with{" "}
          <span className="text-[#00d4ff]">ML-DSA-65 signed attestations</span>, score supply
          chain risk across 5 signals, scan sdist tarballs for malicious patterns, and seal your
          SBOM with hybrid post-quantum cryptography.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-col sm:flex-row gap-4 justify-center mb-16"
        >
          <a
            href="#tool"
            className="group inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] text-white font-bold text-base hover:opacity-90 transition-opacity animate-quantum-pulse"
          >
            Analyze Dependencies
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </a>
          <a
            href="#how-it-works"
            className="inline-flex items-center gap-2 px-8 py-4 rounded-xl border border-white/20 text-gray-300 font-medium text-base hover:bg-white/5 hover:text-white transition-all"
          >
            <Shield className="w-4 h-4 text-[#00d4ff]" />
            How It Works
          </a>
        </motion.div>

        {/* Stats bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto"
        >
          {STATS.map((stat) => (
            <div
              key={stat.label}
              className="glass-card rounded-xl p-4 text-center"
              style={{ borderColor: `${stat.color}20` }}
            >
              <p className="text-2xl font-bold mb-1" style={{ color: stat.color }}>
                {stat.value}
              </p>
              <p className="text-xs text-gray-500">{stat.label}</p>
            </div>
          ))}
        </motion.div>

        {/* Feature chips */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="mt-10 flex flex-wrap justify-center gap-2"
        >
          {[
            "Levenshtein Detection",
            "Homoglyph Normalization",
            "ML-DSA-65 Attestations",
            "CVE Risk Scoring",
            "Static Source Scan",
            "CycloneDX SBOM",
            "SPDX License Map",
            "Ed25519 Hybrid",
          ].map((chip) => (
            <span
              key={chip}
              className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-gray-500 font-mono"
            >
              {chip}
            </span>
          ))}
        </motion.div>
      </div>

      {/* Scroll cue */}
      <motion.div
        animate={{ y: [0, 6, 0] }}
        transition={{ duration: 2, repeat: Infinity }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1 text-gray-600"
      >
        <div className="w-px h-8 bg-gradient-to-b from-transparent to-[#00d4ff]/50" />
        <Lock className="w-3 h-3 text-[#00d4ff]/50" />
      </motion.div>
    </section>
  );
}

function LatticeNodes() {
  const nodes = [
    { x: 8, y: 18, delay: 0 },
    { x: 88, y: 14, delay: 0.5 },
    { x: 18, y: 78, delay: 1 },
    { x: 92, y: 72, delay: 1.5 },
    { x: 50, y: 8, delay: 0.3 },
    { x: 12, y: 52, delay: 0.8 },
    { x: 82, y: 47, delay: 1.2 },
    { x: 47, y: 88, delay: 0.6 },
  ];

  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden">
      {nodes.map((n, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: [0.2, 0.7, 0.2], scale: [1, 1.4, 1] }}
          transition={{ duration: 3, repeat: Infinity, delay: n.delay }}
          className="absolute w-2 h-2 rounded-full bg-[#00d4ff]"
          style={{ left: `${n.x}%`, top: `${n.y}%` }}
        />
      ))}
      <svg className="absolute inset-0 w-full h-full opacity-10">
        <line x1="8%" y1="18%" x2="50%" y2="8%" stroke="#00d4ff" strokeWidth="0.5" />
        <line x1="50%" y1="8%" x2="88%" y2="14%" stroke="#00d4ff" strokeWidth="0.5" />
        <line x1="8%" y1="18%" x2="12%" y2="52%" stroke="#7c3aed" strokeWidth="0.5" />
        <line x1="88%" y1="14%" x2="82%" y2="47%" stroke="#7c3aed" strokeWidth="0.5" />
        <line x1="12%" y1="52%" x2="18%" y2="78%" stroke="#00d4ff" strokeWidth="0.5" />
        <line x1="82%" y1="47%" x2="92%" y2="72%" stroke="#00d4ff" strokeWidth="0.5" />
        <line x1="47%" y1="88%" x2="18%" y2="78%" stroke="#7c3aed" strokeWidth="0.5" />
        <line x1="47%" y1="88%" x2="92%" y2="72%" stroke="#7c3aed" strokeWidth="0.5" />
      </svg>
    </div>
  );
}
