import { Shield, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

export default function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-panel border-b border-white/5 h-20 flex items-center">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full flex justify-between items-center">
        
        <div className="flex items-center space-x-3">
          <div className="relative">
            <Shield className="w-8 h-8 text-primary" />
            <motion.div 
              animate={{ opacity: [0.2, 0.8, 0.2] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="absolute inset-0 bg-primary blur-md -z-10"
            />
          </div>
          <span className="text-xl font-bold tracking-tight text-white">
            Lattice<span className="text-primary">Guard</span>
          </span>
        </div>

        <div className="hidden md:flex items-center space-x-8">
          <a href="#how-it-works" className="text-sm text-muted-foreground hover:text-white transition-colors">How It Works</a>
          <a href="#sign" className="text-sm text-muted-foreground hover:text-white transition-colors">Sign SBOM</a>
          <a href="#verify" className="text-sm text-muted-foreground hover:text-white transition-colors">Verify</a>
          <a href="#comparison" className="text-sm text-muted-foreground hover:text-white transition-colors">PQC Specs</a>
        </div>

        <div className="flex items-center">
          <div className="px-3 py-1.5 rounded-full bg-success/10 border border-success/30 flex items-center space-x-2 glow-success">
            <ShieldCheck className="w-4 h-4 text-success" />
            <span className="text-xs font-bold text-success uppercase tracking-wider">FIPS 204 Compliant</span>
          </div>
        </div>
      </div>
    </nav>
  );
}
