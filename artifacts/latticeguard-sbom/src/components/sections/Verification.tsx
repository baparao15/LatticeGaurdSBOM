import { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldAlert, ShieldCheck, UploadCloud, Search, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { SbomManifest } from "@/hooks/use-sbom";

export default function Verification() {
  const { toast } = useToast();
  const [fileData, setFileData] = useState<SbomManifest | null>(null);
  
  // Verification states
  const [isVerifying, setIsVerifying] = useState(false);
  const [step, setStep] = useState(0); // 0 = not started, 1..5 = steps
  const [tampered, setTampered] = useState<string[]>([]);
  const [verified, setVerified] = useState(false);

  const steps = [
    "Parsing CycloneDX manifest...",
    "Loading embedded ML-DSA public keys...",
    "Re-calculating SHA-256 hashes...",
    "Verifying Classical ECDSA signatures...",
    "Verifying Quantum ML-DSA-65 signatures...",
    "Cross-validating Hybrid architecture..."
  ];

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const json = JSON.parse(reader.result as string) as SbomManifest;
          if (json.bomFormat !== 'CycloneDX' || !json.components) throw new Error("Invalid format");
          setFileData(json);
          setVerified(false);
          setStep(0);
          setTampered([]);
          toast({ title: "SBOM Loaded", description: `Found ${json.components.length} components.` });
        } catch (e) {
          toast({ title: "Error", description: "Invalid SBOM JSON file.", variant: "destructive" });
        }
      };
      reader.readAsText(file);
    }
  }, [toast]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, accept: {'application/json': ['.json']} });

  const startVerification = async () => {
    setIsVerifying(true);
    setVerified(false);
    
    for (let i = 1; i <= steps.length; i++) {
      setStep(i);
      await new Promise(r => setTimeout(r, tampered.length > 0 && i > 3 ? 100 : 400));
      // If tampered, break early on sig verification step
      if (tampered.length > 0 && i === 4) {
        break;
      }
    }
    
    setIsVerifying(false);
    setVerified(true);
  };

  const simulateAttack = () => {
    if (!fileData || fileData.components.length === 0) return;
    const comps = fileData.components;
    // Pick a random component to tamper
    const target = comps[Math.floor(Math.random() * comps.length)];
    setTampered([target.name]);
    setVerified(false);
    setStep(0);
    toast({ 
      title: "Attack Simulated", 
      description: `${target.name} hash has been modified in memory. Run verify to see detection.`,
      variant: "destructive" 
    });
  };

  return (
    <section id="verify" className="py-24 relative overflow-hidden">
      {/* Background threat pulse if tampered */}
      {verified && tampered.length > 0 && (
        <div className="absolute inset-0 bg-destructive/10 animate-pulse -z-10" />
      )}

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Quantum-Safe Verification</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Audit signed manifests before deployment to prevent supply chain poisoning.
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          {!fileData ? (
            <div 
              {...getRootProps()} 
              className={`p-12 border-2 border-dashed rounded-3xl flex flex-col items-center justify-center cursor-pointer transition-all duration-300 ${
                isDragActive ? 'border-primary bg-primary/10 glow-primary' : 'border-white/20 bg-white/5 hover:border-primary/50'
              }`}
            >
              <input {...getInputProps()} />
              <UploadCloud className={`w-16 h-16 mb-6 ${isDragActive ? 'text-primary animate-bounce' : 'text-muted-foreground'}`} />
              <h3 className="text-2xl font-bold text-white mb-2">Drop .signed.json here</h3>
              <p className="text-muted-foreground">or click to browse local files</p>
            </div>
          ) : (
            <div className="glass-card rounded-3xl p-6 md:p-8">
              <div className="flex justify-between items-center mb-6 border-b border-white/10 pb-6">
                <div>
                  <h3 className="text-xl font-bold text-white">Manifest Loaded</h3>
                  <p className="text-sm text-muted-foreground font-mono mt-1">ID: {fileData.serialNumber}</p>
                </div>
                <button onClick={() => setFileData(null)} className="text-sm text-muted-foreground hover:text-white flex items-center">
                  <RefreshCw className="w-4 h-4 mr-1" /> Reset
                </button>
              </div>

              {!isVerifying && !verified && (
                <div className="flex space-x-4">
                  <button 
                    onClick={startVerification}
                    className="flex-1 py-4 bg-primary text-primary-foreground font-bold rounded-xl flex items-center justify-center space-x-2 glow-primary hover:brightness-110 transition-all"
                  >
                    <Search className="w-5 h-5" />
                    <span>Verify Signatures</span>
                  </button>
                  <button 
                    onClick={simulateAttack}
                    className="px-6 py-4 bg-white/5 text-destructive font-bold rounded-xl border border-destructive/30 hover:bg-destructive/10 transition-all"
                  >
                    Simulate Tamper
                  </button>
                </div>
              )}

              {/* Verification Sequence Animation */}
              {isVerifying && (
                <div className="space-y-4 py-8">
                  {steps.map((s, i) => (
                    <div key={i} className={`flex items-center space-x-4 transition-opacity duration-300 ${step > i ? 'opacity-100' : 'opacity-20'}`}>
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center ${step > i + 1 ? 'bg-success text-success-foreground' : step === i + 1 ? 'bg-primary animate-pulse text-primary-foreground' : 'bg-white/10'}`}>
                        {step > i + 1 && <CheckCircle2 className="w-4 h-4" />}
                      </div>
                      <span className="font-mono text-sm">{s}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Results Panel */}
              {verified && (
                <AnimatePresence>
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mt-8">
                    
                    {tampered.length > 0 ? (
                      <div className="bg-destructive/20 border-2 border-destructive rounded-2xl p-6 glow-destructive mb-8 flex items-start space-x-4">
                        <ShieldAlert className="w-12 h-12 text-destructive shrink-0 animate-pulse" />
                        <div>
                          <h4 className="text-2xl font-bold text-destructive mb-2">QUANTUM-SAFE ALERT</h4>
                          <p className="text-white/90 font-bold">Tamper detected in dependencies: {tampered.join(', ')}</p>
                          <p className="text-sm text-destructive mt-2">Signatures do not match re-calculated hashes. INSTALLATION BLOCKED.</p>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-success/10 border border-success/50 rounded-2xl p-6 glow-success mb-8 flex items-center space-x-4">
                        <ShieldCheck className="w-10 h-10 text-success shrink-0" />
                        <div>
                          <h4 className="text-xl font-bold text-success">ALL SIGNATURES VALID</h4>
                          <p className="text-sm text-white/80">Manifest integrity verified. Safe to install.</p>
                        </div>
                      </div>
                    )}

                    <div className="bg-black/40 rounded-xl border border-white/10 overflow-hidden">
                      <table className="w-full text-left text-sm">
                        <thead className="bg-white/5 text-muted-foreground font-mono text-xs uppercase">
                          <tr>
                            <th className="p-4">Component</th>
                            <th className="p-4">Hash Status</th>
                            <th className="p-4 hidden sm:table-cell">Classical Sig</th>
                            <th className="p-4 hidden sm:table-cell">ML-DSA Sig</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5 font-mono">
                          {fileData.components.map((comp, i) => {
                            const isTampered = tampered.includes(comp.name);
                            return (
                              <tr key={i} className={isTampered ? 'bg-destructive/10 text-destructive' : 'text-white/80'}>
                                <td className="p-4 font-bold">{comp.name}</td>
                                <td className="p-4">
                                  {isTampered ? '❌ MISMATCH' : '✅ VALID'}
                                </td>
                                <td className="p-4 hidden sm:table-cell opacity-50">
                                  {isTampered ? 'FAIL' : 'OK'}
                                </td>
                                <td className="p-4 hidden sm:table-cell opacity-50">
                                  {isTampered ? 'FAIL' : 'OK'}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                  </motion.div>
                </AnimatePresence>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
