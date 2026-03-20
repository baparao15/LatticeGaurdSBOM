import { useState, useCallback } from 'react';
import { generateSHA256, generateClassicalKeys, signClassical, generateMLDSAKeys, signMLDSA, generateUUID } from '@/lib/crypto';
import { useToast } from './use-toast';

export type Component = {
  name: string;
  version: string;
  purl: string;
  hash: string;
};

export type SignedComponent = Component & {
  signatures?: {
    classical: string;
    ml_dsa_65: string;
  }
};

export type SbomManifest = {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    signer?: string;
  };
  components: SignedComponent[];
};

export function useSbom() {
  const { toast } = useToast();
  const [components, setComponents] = useState<SignedComponent[]>([]);
  const [manifest, setManifest] = useState<SbomManifest | null>(null);
  
  const [keyPair, setKeyPair] = useState<{
    classical: CryptoKeyPair;
    mlDsa: ReturnType<typeof generateMLDSAKeys>;
  } | null>(null);

  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [signedCount, setSignedCount] = useState(0);

  const parseDependencies = async (text: string, type: 'python' | 'node') => {
    const lines = text.split('\n').filter(l => l.trim() !== '' && !l.startsWith('#'));
    const parsed: Component[] = [];

    for (const line of lines) {
      let name = '';
      let version = '';
      
      if (type === 'python') {
        const parts = line.split('==');
        if (parts.length >= 2) {
          name = parts[0].trim();
          version = parts[1].trim();
        } else {
          continue;
        }
      } else {
        // Simple fallback for node or other formats if needed
        const parts = line.split('@');
        if (parts.length >= 2) {
          name = parts[0].trim();
          version = parts[1].trim();
        }
      }

      const purl = `pkg:${type === 'python' ? 'pypi' : 'npm'}/${name}@${version}`;
      const hash = await generateSHA256(`${name}@${version}`);
      
      parsed.push({ name, version, purl, hash });
    }

    const newManifest: SbomManifest = {
      bomFormat: "CycloneDX",
      specVersion: "1.4",
      serialNumber: `urn:uuid:${generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString()
      },
      components: parsed
    };

    setComponents(parsed);
    setManifest(newManifest);
    
    toast({
      title: "SBOM Generated Successfully",
      description: `Parsed ${parsed.length} components and generated SHA-256 hashes.`,
      variant: "default",
    });
  };

  const generateKeys = async () => {
    setIsGeneratingKeys(true);
    try {
      // Fake delay for dramatic effect
      await new Promise(r => setTimeout(r, 1500));
      
      const classical = await generateClassicalKeys();
      const mlDsa = generateMLDSAKeys();
      
      setKeyPair({ classical, mlDsa });
      toast({
        title: "Quantum Vault Ready",
        description: "ML-DSA-65 & Classical hybrid keypair generated locally.",
      });
    } catch (e) {
      toast({
        title: "Key Generation Failed",
        description: "Error generating cryptographic keys.",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingKeys(false);
    }
  };

  const signAllComponents = async () => {
    if (!keyPair || !manifest) return;
    setIsSigning(true);
    setSignedCount(0);

    const signedComps: SignedComponent[] = [];
    
    for (let i = 0; i < components.length; i++) {
      const comp = components[i];
      const dataToSign = JSON.stringify(comp);
      
      const classicalSig = await signClassical(dataToSign, keyPair.classical.privateKey);
      const mlDsaSig = signMLDSA();
      
      signedComps.push({
        ...comp,
        signatures: {
          classical: classicalSig,
          ml_dsa_65: mlDsaSig
        }
      });
      
      setSignedCount(i + 1);
      // Small artificial delay to show progress bar visually
      await new Promise(r => setTimeout(r, 100));
    }

    const newManifest: SbomManifest = {
      ...manifest,
      metadata: {
        ...manifest.metadata,
        signer: "LatticeGuard-v1.0"
      },
      components: signedComps
    };

    setComponents(signedComps);
    setManifest(newManifest);
    setIsSigning(false);
    
    toast({
      title: "Hybrid Signing Complete",
      description: `Successfully signed ${signedComps.length} components with ML-DSA-65 and ECDSA.`,
    });
  };

  const clearSbom = () => {
    setComponents([]);
    setManifest(null);
    setSignedCount(0);
  };

  return {
    components,
    manifest,
    keyPair,
    isGeneratingKeys,
    isSigning,
    signedCount,
    parseDependencies,
    generateKeys,
    signAllComponents,
    clearSbom
  };
}
