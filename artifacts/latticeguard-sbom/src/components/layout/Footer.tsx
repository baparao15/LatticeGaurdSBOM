import { Github, Code2, Shield } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-white/5 py-12 relative z-10 bg-background/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row justify-between items-center">
          
          <div className="flex items-center space-x-3 mb-6 md:mb-0">
            <Shield className="w-6 h-6 text-muted-foreground" />
            <div className="flex flex-col">
              <span className="font-bold text-white">LatticeGuard SBOM</span>
              <span className="text-xs text-muted-foreground">Team INFIFNITE | QC² Hackathon 2025</span>
            </div>
          </div>
          
          <div className="flex space-x-6">
            <div className="flex items-center space-x-2 text-muted-foreground hover:text-primary transition-colors cursor-pointer">
              <Code2 className="w-4 h-4" />
              <span className="text-sm">Built with NIST FIPS 204 / ML-DSA-65</span>
            </div>
            <div className="flex items-center space-x-2 text-muted-foreground hover:text-white transition-colors cursor-pointer">
              <Github className="w-4 h-4" />
              <span className="text-sm">GitHub Repo</span>
            </div>
          </div>
          
        </div>
      </div>
    </footer>
  );
}
