import { motion } from "framer-motion";
import { Shield, BarChart2, Search, Clock, Package, CheckCircle } from "lucide-react";

const STAGES = [
  {
    n: "01",
    icon: <Shield className="w-6 h-6" />,
    color: "#00d4ff",
    title: "Pre-Fetch Name Safety Gate",
    subtitle: "Phase 1",
    desc: "Before any network call, every package name is verified against our ML-DSA-65 signed list of 8,000 top PyPI packages. Levenshtein distance ≤2 and homoglyph normalization (0→o, 1→l, rn→m) catch typosquats like numpy-1 or requests-lib.",
    bullets: [
      "ML-DSA-65 signed top-8K list (24h TTL)",
      "Levenshtein distance with O(1) exact cache",
      "Homoglyph normalisation (0→o, rn→m, vv→w)",
      "Padding pattern detection (python-X, X-lib)",
      "Signed attestation per verdict",
    ],
  },
  {
    n: "02",
    icon: <BarChart2 className="w-6 h-6" />,
    color: "#7c3aed",
    title: "5-Signal Risk Scoring",
    subtitle: "Phase 2",
    desc: "Every resolved package receives a 0–100 risk score computed from five independent signals. The score is signed with ML-DSA-65 + Ed25519 and included in the SBOM export.",
    bullets: [
      "CVE severity (0–40 pts): worst single CVE drives the score",
      "Package age (0–20 pts): new packages and single-release packages",
      "Maintainer count (0–15 pts): bus-factor estimate",
      "Download volume (0–15 pts): pypistats.org monthly count",
      "Name check result (0–10 pts): typosquat penalty",
    ],
  },
  {
    n: "03",
    icon: <Search className="w-6 h-6" />,
    color: "#ff3366",
    title: "Static Source Scan",
    subtitle: "Phase 3",
    desc: "For packages that ship an sdist tar.gz, LatticeGuard downloads the archive in-memory (without executing it) and scans install-time files for malicious patterns.",
    bullets: [
      "Scans setup.py, setup.cfg, pyproject.toml, __init__.py",
      "Detects exec(base64.b64decode(…)) and eval obfuscation",
      "Flags subprocess/os.system in install scripts",
      "Catches network calls during pip install",
      "Detects credential harvesting (AWS_, GITHUB_TOKEN, .ssh)",
    ],
  },
  {
    n: "04",
    icon: <Clock className="w-6 h-6" />,
    color: "#00ff88",
    title: "PQC Audit Log Timeline",
    subtitle: "Phase 4",
    desc: "Every cryptographic event — list fetch, name check, risk score, static scan, SBOM signing — is appended to an immutable audit log. Each event is independently signed with ML-DSA-65 + Ed25519.",
    bullets: [
      "Tamper-evident — every event carries a unique signature",
      "Events: NAME_LIST_FETCHED, NAME_CHECK, RISK_SCORED, STATIC_SCAN, SBOM_SIGNED",
      "ML-DSA-65 + Ed25519 hybrid per event",
      "3,357 bytes of signature data per event",
      "Session-scoped — cleared on server restart",
    ],
  },
  {
    n: "05",
    icon: <Package className="w-6 h-6" />,
    color: "#ff9900",
    title: "Sign & 6-File Export",
    subtitle: "Phase 7",
    desc: "After review, generate a session ML-DSA-65 + Ed25519 keypair and sign every component. The export ZIP contains 6 files covering the complete cryptographic chain from name-check through SBOM signing.",
    bullets: [
      "latticeguard-sbom.json — CycloneDX 1.5 SBOM",
      "name-attestations.json — signed per-name verdicts",
      "static-scan-results.json — signed scan findings",
      "risk-scores.json — signed 0-100 scores",
      "public-keys.pem — ML-DSA-65 + Ed25519 public keys",
      "verify.py — offline verifier (pip install cryptography)",
    ],
  },
];

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="py-24 px-4 relative">
      <div className="absolute inset-0 lattice-bg opacity-20" />

      <div className="max-w-4xl mx-auto relative">
        <div className="text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#00d4ff]/10 border border-[#00d4ff]/20 mb-4"
          >
            <CheckCircle className="w-3.5 h-3.5 text-[#00d4ff]" />
            <span className="text-xs text-[#00d4ff] font-medium">8-Phase Security Pipeline</span>
          </motion.div>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-4xl font-bold text-white mb-4"
          >
            How LatticeGuard Works
          </motion.h2>
          <p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">
            Five automated stages run from dependency resolution through quantum-safe SBOM export —
            every step signed, every verdict recorded.
          </p>
        </div>

        {/* Vertical timeline */}
        <div className="relative">
          {/* Vertical connector line */}
          <div className="absolute left-8 top-0 bottom-0 w-px bg-gradient-to-b from-[#00d4ff]/40 via-[#7c3aed]/40 to-[#ff9900]/40" />

          <div className="space-y-8">
            {STAGES.map((stage, i) => (
              <motion.div
                key={stage.n}
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="relative flex gap-6"
              >
                {/* Node */}
                <div
                  className="relative z-10 flex-shrink-0 w-16 h-16 rounded-xl flex items-center justify-center border"
                  style={{
                    backgroundColor: `${stage.color}12`,
                    borderColor: `${stage.color}30`,
                    color: stage.color,
                  }}
                >
                  {stage.icon}
                  <div
                    className="absolute -top-1 -right-1 w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-bold text-black"
                    style={{ backgroundColor: stage.color }}
                  >
                    {stage.n}
                  </div>
                </div>

                {/* Card */}
                <div className="glass-card rounded-2xl p-5 flex-1 mb-2">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <span
                        className="text-xs font-mono font-bold uppercase tracking-wider"
                        style={{ color: stage.color }}
                      >
                        {stage.subtitle}
                      </span>
                      <h3 className="text-base font-bold text-white mt-0.5">{stage.title}</h3>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm leading-relaxed mb-3">{stage.desc}</p>
                  <div className="flex flex-wrap gap-2">
                    {stage.bullets.map((b, j) => (
                      <span
                        key={j}
                        className="text-xs px-2 py-0.5 rounded bg-white/5 border border-white/10 text-gray-400"
                      >
                        ✓ {b}
                      </span>
                    ))}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
