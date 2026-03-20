import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSbom } from "@/hooks/use-sbom";
import { FileJson, Hash, Key, Lock, Download, Share2, CheckCircle2, Copy } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function MainTool() {
  const [activeTab, setActiveTab] = useState<'generate' | 'sign' | 'export'>('generate');
  const sbom = useSbom();

  return (
    <section id="sign" className="py-24 relative z-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">LatticeGuard Core</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Generate and cryptographically sign your SBOMs in the browser.
          </p>
        </div>

        <div className="glass-card rounded-3xl overflow-hidden shadow-2xl border-white/10">
          {/* Custom Tabs Header */}
          <div className="flex flex-col sm:flex-row border-b border-white/10 bg-black/20">
            {[
              { id: 'generate', label: '1. Generate SBOM', icon: <FileJson className="w-4 h-4" /> },
              { id: 'sign', label: '2. Quantum Sign', icon: <Key className="w-4 h-4" /> },
              { id: 'export', label: '3. Export & Share', icon: <Share2 className="w-4 h-4" /> },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex-1 flex items-center justify-center space-x-2 py-4 px-6 text-sm font-bold transition-all relative ${
                  activeTab === tab.id ? 'text-primary' : 'text-muted-foreground hover:text-white'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {activeTab === tab.id && (
                  <motion.div 
                    layoutId="activeTabIndicator"
                    className="absolute bottom-0 left-0 right-0 h-1 bg-primary glow-primary"
                  />
                )}
              </button>
            ))}
          </div>

          <div className="p-6 md:p-10 min-h-[500px]">
            <AnimatePresence mode="wait">
              {activeTab === 'generate' && <GenerateTab key="generate" sbom={sbom} onNext={() => setActiveTab('sign')} />}
              {activeTab === 'sign' && <SignTab key="sign" sbom={sbom} onNext={() => setActiveTab('export')} />}
              {activeTab === 'export' && <ExportTab key="export" sbom={sbom} />}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}

// --- TAB COMPONENTS ---

function GenerateTab({ sbom, onNext }: { sbom: ReturnType<typeof useSbom>, onNext: () => void }) {
  const [input, setInput] = useState("flask==2.3.0\nnumpy==1.24.0\nrequests==2.31.0\ncryptography==41.0.0");
  
  return (
    <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        <div className="space-y-4">
          <label className="text-sm font-bold text-muted-foreground uppercase tracking-wider">Paste Dependencies (requirements.txt)</label>
          <textarea 
            className="w-full h-64 bg-black/40 border border-white/10 rounded-xl p-4 font-mono text-sm text-primary focus:border-primary focus:ring-1 focus:ring-primary transition-all resize-none"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="flask==2.3.0..."
          />
          <button 
            onClick={() => sbom.parseDependencies(input, 'python')}
            className="w-full py-3 rounded-xl bg-primary text-primary-foreground font-bold hover:brightness-110 transition-all glow-primary flex items-center justify-center space-x-2"
          >
            <Hash className="w-5 h-5" />
            <span>Generate SBOM & Hashes</span>
          </button>
        </div>

        <div className="space-y-4">
          <label className="text-sm font-bold text-muted-foreground uppercase tracking-wider">SBOM Preview (CycloneDX)</label>
          <div className="w-full h-[330px] bg-black/60 border border-white/5 rounded-xl p-4 overflow-auto relative">
            {!sbom.manifest ? (
              <div className="absolute inset-0 flex items-center justify-center text-muted-foreground">
                <p>Generate to preview JSON...</p>
              </div>
            ) : (
              <pre className="font-mono text-xs text-white/80">
                {JSON.stringify(sbom.manifest, null, 2)}
              </pre>
            )}
          </div>
          {sbom.manifest && (
            <button onClick={onNext} className="w-full py-2 border border-primary/50 text-primary rounded-xl hover:bg-primary/10 transition-colors font-bold">
              Proceed to Sign →
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}

function SignTab({ sbom, onNext }: { sbom: ReturnType<typeof useSbom>, onNext: () => void }) {
  if (!sbom.manifest) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
        <FileJson className="w-12 h-12 mb-4 opacity-50" />
        <p>Please generate an SBOM first.</p>
      </div>
    );
  }

  const allSigned = sbom.signedCount === sbom.components.length && sbom.components.length > 0;

  return (
    <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        
        {/* Left Col - Key Vault */}
        <div className="glass-panel rounded-2xl p-6 border-white/5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-primary" />
          <h3 className="text-xl font-bold mb-6 flex items-center space-x-2">
            <Key className="text-secondary w-5 h-5" />
            <span>Quantum Key Vault</span>
          </h3>

          {!sbom.keyPair ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-16 h-16 bg-secondary/10 rounded-full flex items-center justify-center mb-4 glow-secondary">
                <Lock className="w-8 h-8 text-secondary" />
              </div>
              <button 
                onClick={sbom.generateKeys}
                disabled={sbom.isGeneratingKeys}
                className="px-6 py-3 rounded-xl bg-secondary text-white font-bold hover:brightness-110 transition-all glow-secondary flex items-center space-x-2 disabled:opacity-50"
              >
                {sbom.isGeneratingKeys ? (
                  <span className="animate-pulse">Generating Lattice Matrices...</span>
                ) : (
                  <span>Generate ML-DSA-65 Keypair</span>
                )}
              </button>
              <p className="mt-4 text-xs text-muted-foreground">Generated securely in your browser. Private key never leaves this device.</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="p-4 bg-black/40 rounded-xl border border-white/10">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-xs text-success font-bold uppercase tracking-wider">Active Algorithm</span>
                  <span className="text-xs text-muted-foreground border border-white/10 px-2 py-1 rounded">FIPS 204 Level 3</span>
                </div>
                <div className="text-lg font-mono text-white">ML-DSA-65 + ECDSA Hybrid</div>
              </div>
              
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground uppercase">ML-DSA Public Key ({sbom.keyPair.mlDsa.publicKeyBytes} bytes)</label>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 bg-black/50 p-2 rounded text-xs text-secondary truncate">
                    {sbom.keyPair.mlDsa.publicKeyHex}
                  </code>
                  <button className="p-2 bg-white/5 hover:bg-white/10 rounded transition-colors text-white"><Copy className="w-4 h-4"/></button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-xs text-muted-foreground uppercase">Private Key ({sbom.keyPair.mlDsa.privateKeyBytes} bytes)</label>
                <code className="block w-full bg-black/50 p-2 rounded text-xs text-white/30 tracking-widest">
                  ●●●●●●●●●●●●●●●●●●●●●●●●●
                </code>
              </div>
            </div>
          )}
        </div>

        {/* Right Col - Components List */}
        <div className="flex flex-col h-full">
          <div className="flex justify-between items-end mb-4">
            <h3 className="text-xl font-bold">Sign Components</h3>
            <span className="text-sm text-muted-foreground">{sbom.signedCount} / {sbom.components.length} Signed</span>
          </div>

          <div className="flex-1 bg-black/40 border border-white/10 rounded-2xl overflow-hidden flex flex-col">
            <div className="flex-1 overflow-y-auto p-2 space-y-2 max-h-[300px]">
              {sbom.components.map((comp, i) => {
                const isSigned = i < sbom.signedCount;
                return (
                  <div key={i} className={`p-3 rounded-xl border transition-all ${isSigned ? 'bg-success/5 border-success/30' : 'bg-white/5 border-white/5'}`}>
                    <div className="flex justify-between items-center">
                      <div>
                        <span className="font-mono text-sm text-white">{comp.name}</span>
                        <span className="text-xs text-muted-foreground ml-2">@{comp.version}</span>
                      </div>
                      {isSigned && <CheckCircle2 className="w-4 h-4 text-success" />}
                    </div>
                    {isSigned && comp.signatures && (
                      <div className="mt-2 text-[10px] font-mono text-muted-foreground truncate opacity-60">
                        Sig: {comp.signatures.ml_dsa_65.substring(0,24)}...
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
            
            <div className="p-4 border-t border-white/10 bg-black/60">
              <button 
                onClick={sbom.signAllComponents}
                disabled={!sbom.keyPair || sbom.isSigning || allSigned}
                className={`w-full py-3 rounded-xl font-bold transition-all flex items-center justify-center space-x-2 ${
                  allSigned ? 'bg-success/20 text-success border border-success/50' : 
                  sbom.keyPair ? 'bg-primary text-primary-foreground hover:brightness-110 glow-primary' : 'bg-white/5 text-muted-foreground cursor-not-allowed'
                }`}
              >
                {sbom.isSigning ? (
                  <span>Signing Component {sbom.signedCount + 1}...</span>
                ) : allSigned ? (
                  <>
                    <CheckCircle2 className="w-5 h-5" />
                    <span>All Signed ({sbom.components.length})</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-5 h-5" />
                    <span>Sign with Hybrid Engine</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {allSigned && (
            <button onClick={onNext} className="mt-4 w-full py-2 border border-primary/50 text-primary rounded-xl hover:bg-primary/10 transition-colors font-bold">
              Review Final SBOM →
            </button>
          )}

        </div>
      </div>
    </motion.div>
  );
}

function ExportTab({ sbom }: { sbom: ReturnType<typeof useSbom> }) {
  const { toast } = useToast();

  if (!sbom.manifest || !sbom.manifest.components[0]?.signatures) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
        <Lock className="w-12 h-12 mb-4 opacity-50" />
        <p>Please sign the SBOM first.</p>
      </div>
    );
  }

  const handleDownload = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(sbom.manifest, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", "sbom.signed.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();

    toast({ title: "SBOM Downloaded" });
  };

  return (
    <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
      <div className="flex flex-col items-center max-w-2xl mx-auto space-y-8">
        
        <div className="w-16 h-16 bg-success/20 rounded-full flex items-center justify-center glow-success">
          <CheckCircle2 className="w-8 h-8 text-success" />
        </div>
        
        <div className="text-center">
          <h3 className="text-2xl font-bold mb-2">Manifest Cryptographically Secured</h3>
          <p className="text-muted-foreground">
            Your SBOM is now signed with ML-DSA-65 and Classical ECDSA. It is ready for distribution.
          </p>
        </div>

        <div className="w-full grid grid-cols-1 md:grid-cols-2 gap-4">
          <button 
            onClick={handleDownload}
            className="p-4 glass-panel rounded-xl hover:bg-white/10 transition-all flex flex-col items-center justify-center space-y-2 group"
          >
            <Download className="w-6 h-6 text-primary group-hover:-translate-y-1 transition-transform" />
            <span className="font-bold text-white">sbom.signed.json</span>
            <span className="text-xs text-muted-foreground">~{(JSON.stringify(sbom.manifest).length / 1024).toFixed(1)} KB</span>
          </button>

          <button 
            onClick={() => {
              if (sbom.keyPair) {
                 const data = "data:text/plain;charset=utf-8," + encodeURIComponent(sbom.keyPair.mlDsa.publicKeyHex);
                 const a = document.createElement('a');
                 a.href = data; a.download = "mldsa_public.key"; a.click();
              }
            }}
            className="p-4 glass-panel rounded-xl hover:bg-white/10 transition-all flex flex-col items-center justify-center space-y-2 group"
          >
            <Key className="w-6 h-6 text-secondary group-hover:-translate-y-1 transition-transform" />
            <span className="font-bold text-white">Public Key</span>
            <span className="text-xs text-muted-foreground">ML-DSA-65 format</span>
          </button>
        </div>

        <div className="w-full bg-black/40 border border-white/10 rounded-xl p-4 overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-muted-foreground uppercase">JSON Snippet</span>
          </div>
          <pre className="font-mono text-xs text-primary/70 overflow-x-auto h-32">
            {JSON.stringify(sbom.manifest, null, 2)}
          </pre>
        </div>

      </div>
    </motion.div>
  );
}
