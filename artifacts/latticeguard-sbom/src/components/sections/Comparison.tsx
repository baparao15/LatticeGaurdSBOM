import { motion } from "framer-motion";

export default function Comparison() {
  return (
    <section id="comparison" className="py-24 relative bg-black/40 border-t border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Classical vs Quantum-Safe</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Why migrate to ML-DSA? Comparing traditional signatures against post-quantum cryptography.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-16">
          {/* Classical Card */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}
            className="p-8 rounded-3xl bg-destructive/5 border border-destructive/20 relative overflow-hidden group"
          >
            <div className="absolute top-0 right-0 p-4 opacity-10 font-mono text-9xl font-bold pointer-events-none group-hover:scale-110 transition-transform">R</div>
            <h3 className="text-2xl font-bold text-white mb-6">Classical Signatures</h3>
            
            <ul className="space-y-4 font-mono text-sm">
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Algorithm</span>
                <span className="text-white">RSA-2048 / ECDSA</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Signature Size</span>
                <span className="text-white">~64 to 256 bytes</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Quantum Resistant</span>
                <span className="text-destructive font-bold">❌ NO</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Breakable by Shor's</span>
                <span className="text-destructive font-bold">✅ YES</span>
              </li>
              <li className="flex justify-between pb-2">
                <span className="text-muted-foreground">NIST Status</span>
                <span className="text-warning">Being deprecated</span>
              </li>
            </ul>
          </motion.div>

          {/* PQC Card */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}
            className="p-8 rounded-3xl bg-success/5 border border-success/30 relative overflow-hidden group glow-success"
          >
            <div className="absolute top-0 right-0 p-4 opacity-10 font-mono text-9xl font-bold pointer-events-none group-hover:scale-110 transition-transform">L</div>
            <h3 className="text-2xl font-bold text-success mb-6">Quantum-Safe (LatticeGuard)</h3>
            
            <ul className="space-y-4 font-mono text-sm">
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Algorithm</span>
                <span className="text-white font-bold">ML-DSA-65 (Hybrid)</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Signature Size</span>
                <span className="text-white">2,420 bytes</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Quantum Resistant</span>
                <span className="text-success font-bold">✅ YES</span>
              </li>
              <li className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-muted-foreground">Breakable by Shor's</span>
                <span className="text-success font-bold">❌ NO</span>
              </li>
              <li className="flex justify-between pb-2">
                <span className="text-muted-foreground">NIST Status</span>
                <span className="text-success font-bold">FIPS 204 Approved</span>
              </li>
            </ul>
          </motion.div>
        </div>

        {/* Bar Chart */}
        <div className="max-w-3xl mx-auto glass-card p-8 rounded-2xl">
          <h4 className="text-center font-bold text-white mb-8">Resistance to Cryptographically Relevant Quantum Computers (CRQC)</h4>
          <div className="space-y-6">
            <div>
              <div className="flex justify-between text-xs font-mono mb-2 text-muted-foreground"><span>RSA-2048</span><span>0%</span></div>
              <div className="w-full bg-black/50 rounded-full h-4 overflow-hidden">
                <motion.div initial={{ width: 0 }} whileInView={{ width: '5%' }} transition={{ duration: 1, delay: 0.2 }} className="bg-destructive h-full" />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs font-mono mb-2 text-muted-foreground"><span>ECC-256</span><span>0%</span></div>
              <div className="w-full bg-black/50 rounded-full h-4 overflow-hidden">
                <motion.div initial={{ width: 0 }} whileInView={{ width: '2%' }} transition={{ duration: 1, delay: 0.4 }} className="bg-destructive h-full" />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs font-mono mb-2 font-bold text-success"><span>ML-DSA-65</span><span>100% Secure</span></div>
              <div className="w-full bg-black/50 rounded-full h-4 overflow-hidden glow-success">
                <motion.div initial={{ width: 0 }} whileInView={{ width: '100%' }} transition={{ duration: 1.5, delay: 0.6 }} className="bg-success h-full" />
              </div>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}
