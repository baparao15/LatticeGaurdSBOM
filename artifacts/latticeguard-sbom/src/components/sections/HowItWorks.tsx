import { motion } from "framer-motion";
import { FileCode, Hash, Key, ShieldCheck } from "lucide-react";

export default function HowItWorks() {
  const steps = [
    { icon: <FileCode />, title: "Upload Manifest", desc: "Input requirements.txt or package.json" },
    { icon: <Hash />, title: "SHA-256 Hash", desc: "Generate immutable hash for every dependency" },
    { icon: <Key />, title: "Hybrid Sign", desc: "Sign with ML-DSA-65 + Ed25519 (FIPS 204)" },
    { icon: <ShieldCheck />, title: "Quantum-Safe SBOM", desc: "Export verified CycloneDX JSON" },
  ];

  return (
    <section id="how-it-works" className="py-24 bg-background/50 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">The LatticeGuard Pipeline</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Zero-trust architecture ensuring component-level integrity across your entire software supply chain.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 relative">
          {/* Connector Line (Desktop only) */}
          <div className="hidden md:block absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-primary/50 to-transparent -translate-y-1/2 z-0" />
          
          {steps.map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="glass-card p-6 rounded-2xl flex flex-col items-center text-center relative z-10"
            >
              <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center text-primary mb-4 glow-primary">
                {step.icon}
              </div>
              <h3 className="text-lg font-bold text-white mb-2">{step.title}</h3>
              <p className="text-sm text-muted-foreground">{step.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
