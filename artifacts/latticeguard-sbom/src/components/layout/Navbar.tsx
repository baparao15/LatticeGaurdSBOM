import { Shield, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

export default function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-panel border-b border-white/5 h-16 flex items-center">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full flex justify-between items-center">

        <a href="#" className="flex items-center space-x-3 hover:opacity-80 transition-opacity">
          <div className="relative">
            <Shield className="w-7 h-7 text-primary" />
            <motion.div
              animate={{ opacity: [0.2, 0.8, 0.2] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="absolute inset-0 bg-primary blur-md -z-10"
            />
          </div>
          <span className="text-lg font-bold tracking-tight text-white">
            Lattice<span className="text-primary">Guard</span>
          </span>
        </a>

        <div className="hidden md:flex items-center gap-1">
          <NavLink href="#how-it-works">How It Works</NavLink>
          <NavLink href="#tool">Generate SBOM</NavLink>
          <NavLink href="#verify">Verify</NavLink>
          <NavLink href="#comparison">PQC Specs</NavLink>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-full bg-success/10 border border-success/30 flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-success" />
            <span className="text-xs font-bold text-success uppercase tracking-wider">FIPS 204</span>
          </div>
        </div>
      </div>
    </nav>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      className="px-3 py-2 rounded-lg text-sm text-muted-foreground hover:text-white hover:bg-white/5 transition-all"
    >
      {children}
    </a>
  );
}
