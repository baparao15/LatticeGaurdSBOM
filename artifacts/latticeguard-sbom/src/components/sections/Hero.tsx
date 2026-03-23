import { motion } from "framer-motion";
import { Lock, FileSearch, ShieldCheck, Cpu, Database } from "lucide-react";

export default function Hero() {
  return (
    <section className="relative pt-32 pb-20 md:pt-48 md:pb-32 overflow-hidden flex items-center min-h-[90vh]">
      <div className="absolute inset-0 bg-grid-pattern opacity-20" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/20 rounded-full blur-[120px] -z-10 mix-blend-screen" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-secondary/20 rounded-full blur-[120px] -z-10 mix-blend-screen" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-[#00d4ff]/30 bg-[#00d4ff]/5 text-[#00d4ff] text-sm font-mono mb-6">
              <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              Live backend · Real PyPI/npm · Real CVEs
            </div>
            <h1 className="text-5xl md:text-7xl font-bold tracking-tighter mb-6 leading-tight">
              Quantum-Safe <br />
              Software Supply Chain <br />
              <span className="text-gradient">Security Engine</span>
            </h1>
          </motion.div>

          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed"
          >
            Sign every dependency with <strong className="text-white">ML-DSA-65</strong>.
            Cryptographically unbreakable by both classical and quantum computers.
            Zero-trust pipeline integrity out of the box.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="flex flex-col sm:flex-row justify-center items-center space-y-4 sm:space-y-0 sm:space-x-6"
          >
            <a
              href="#tool"
              className="w-full sm:w-auto px-8 py-4 rounded-xl font-bold text-primary-foreground bg-gradient-to-r from-primary to-primary/80 glow-primary hover:scale-105 transition-transform flex items-center justify-center space-x-2"
            >
              <Lock className="w-5 h-5" />
              <span>Generate SBOM →</span>
            </a>

            <a
              href="#verify"
              className="w-full sm:w-auto px-8 py-4 rounded-xl font-bold text-white glass-card hover:bg-white/10 transition-all flex items-center justify-center space-x-2"
            >
              <FileSearch className="w-5 h-5" />
              <span>Verify SBOM</span>
            </a>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.6 }}
            className="mt-16 flex flex-wrap justify-center gap-4 sm:gap-8"
          >
            <Badge icon={<ShieldCheck />} text="NIST FIPS 204" />
            <Badge icon={<Cpu />} text="ML-DSA-65 · 3293-byte sigs" />
            <Badge icon={<Database />} text="CycloneDX 1.5" />
          </motion.div>

          {/* Quick workflow hint */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.8 }}
            className="mt-12 flex justify-center items-center gap-3 text-sm text-gray-600"
          >
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span className="text-[#00d4ff]">1</span> Paste requirements.txt
            </span>
            <span className="text-gray-700">→</span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span className="text-[#7c3aed]">2</span> Generate ML-DSA-65 keys
            </span>
            <span className="text-gray-700">→</span>
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span className="text-[#00ff88]">3</span> Download signed SBOM
            </span>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function Badge({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="flex items-center space-x-2 px-4 py-2 rounded-full glass-card border-white/5">
      <div className="text-secondary w-4 h-4">{icon}</div>
      <span className="text-sm font-medium text-muted-foreground">{text}</span>
    </div>
  );
}
