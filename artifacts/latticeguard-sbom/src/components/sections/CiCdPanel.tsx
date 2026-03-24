import { useState } from "react";
import { motion } from "framer-motion";
import { Terminal, GitBranch, Shield, Copy, CheckCircle } from "lucide-react";

const TABS = [
  { id: "github", label: "GitHub Actions", icon: <GitBranch className="w-3.5 h-3.5" /> },
  { id: "precommit", label: "pre-commit", icon: <Terminal className="w-3.5 h-3.5" /> },
  { id: "gitlab", label: "GitLab CI", icon: <GitBranch className="w-3.5 h-3.5" /> },
  { id: "badge", label: "Badge", icon: <Shield className="w-3.5 h-3.5" /> },
];

const SNIPPETS: Record<string, string> = {
  github: `name: LatticeGuard SBOM

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sbom:
    name: Generate & Verify PQ-SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install cryptography httpx

      - name: Generate SBOM via LatticeGuard API
        run: |
          curl -s -X POST \\
            https://your-deployment.replit.app/latticeguard-api/packages/resolve \\
            -H "Content-Type: application/json" \\
            -d '{"raw_text":"$(<requirements.txt)","ecosystem":"pypi"}' \\
            > sbom-packages.json

      - name: Verify signatures
        run: python verify.py latticeguard-sbom.json

      - name: Upload SBOM bundle
        uses: actions/upload-artifact@v4
        with:
          name: latticeguard-sbom
          path: latticeguard-sbom-*.zip
          retention-days: 90`,

  precommit: `# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: latticeguard-name-check
        name: LatticeGuard — Package Name Safety Gate
        language: python
        entry: python -c "
import sys, json, urllib.request
reqs = [l.split('==')[0].strip()
        for l in open('requirements.txt')
        if l.strip() and not l.startswith('#')]
body = json.dumps({'names': reqs}).encode()
req = urllib.request.Request(
  'http://localhost:8000/latticeguard-api/namecheck/batch',
  data=body, headers={'Content-Type': 'application/json'})
res = json.loads(urllib.request.urlopen(req).read())
typos = [r for r in res['results']
         if r['verdict'] == 'LIKELY_TYPOSQUAT']
if typos:
  print('TYPOSQUAT DETECTED:', [t['package_name'] for t in typos])
  sys.exit(1)
"
        files: requirements\\.txt
        pass_filenames: false`,

  gitlab: `# .gitlab-ci.yml
stages:
  - security
  - build

latticeguard-sbom:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install cryptography httpx
  script:
    - |
      python3 - <<'EOF'
      import asyncio, httpx, json

      async def run():
          reqs = open("requirements.txt").read()
          async with httpx.AsyncClient(timeout=30) as c:
              r = await c.post(
                  "https://your-deployment.replit.app/latticeguard-api/packages/resolve",
                  json={"raw_text": reqs, "ecosystem": "pypi"}
              )
              data = r.json()
              with open("sbom-data.json", "w") as f:
                  json.dump(data, f, indent=2)
              print(f"Resolved {data['total_found']} packages")

      asyncio.run(run())
      EOF
    - python verify.py latticeguard-sbom.json
  artifacts:
    paths:
      - latticeguard-sbom-*.zip
    expire_in: 90 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`,

  badge: `<!-- LatticeGuard PQ-SBOM Badge -->
<a href="https://your-deployment.replit.app">
  <img
    src="https://img.shields.io/badge/SBOM-ML--DSA--65%20%7C%20FIPS%20204-00d4ff?style=for-the-badge&logo=shield&logoColor=white"
    alt="LatticeGuard PQ-SBOM"
  />
</a>

<!-- Markdown version -->
[![LatticeGuard PQ-SBOM](https://img.shields.io/badge/SBOM-ML--DSA--65%20%7C%20FIPS%20204-00d4ff?style=for-the-badge)](https://your-deployment.replit.app)

<!-- FIPS 204 Badge -->
[![FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-7c3aed?style=for-the-badge&logo=shield)](https://csrc.nist.gov/pubs/fips/204/final)

<!-- Quantum-Safe Badge -->
[![Quantum Safe](https://img.shields.io/badge/Quantum-Safe-00ff88?style=for-the-badge&logo=shield)](https://your-deployment.replit.app)`,
};

export default function CiCdPanel() {
  const [activeTab, setActiveTab] = useState("github");
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(SNIPPETS[activeTab]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="cicd" className="py-20 px-4 relative">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#00d4ff]/10 border border-[#00d4ff]/20 mb-4">
            <Terminal className="w-3.5 h-3.5 text-[#00d4ff]" />
            <span className="text-xs text-[#00d4ff] font-medium">Phase 8 — CI/CD Integration</span>
          </div>
          <h2 className="text-3xl font-bold text-white mb-3">
            Integrate into Your <span className="gradient-text">Pipeline</span>
          </h2>
          <p className="text-gray-400 text-sm max-w-xl mx-auto">
            Add post-quantum SBOM generation and supply chain verification to any CI/CD
            pipeline in minutes.
          </p>
        </div>

        <div className="glass-card rounded-2xl overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-white/10 overflow-x-auto">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3.5 text-sm font-medium whitespace-nowrap transition-all border-b-2 ${
                  activeTab === tab.id
                    ? "border-[#00d4ff] text-[#00d4ff]"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Code block */}
          <div className="relative">
            <button
              onClick={handleCopy}
              className="absolute top-3 right-3 z-10 flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-white/10 hover:bg-white/20 text-xs text-gray-400 hover:text-white transition-all"
            >
              {copied ? (
                <><CheckCircle className="w-3 h-3 text-[#00ff88]" /> Copied</>
              ) : (
                <><Copy className="w-3 h-3" /> Copy</>
              )}
            </button>
            <motion.pre
              key={activeTab}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-5 text-xs font-mono text-gray-300 leading-relaxed overflow-x-auto max-h-[420px] bg-black/30"
            >
              <code>{SNIPPETS[activeTab]}</code>
            </motion.pre>
          </div>

          {/* Feature list */}
          <div className="px-5 py-4 border-t border-white/10 grid sm:grid-cols-3 gap-3">
            {[
              { icon: "🔍", title: "Name Safety Gate", desc: "Block typosquats in every PR" },
              { icon: "📊", title: "Risk Scoring", desc: "Fail builds above threshold" },
              { icon: "✍️", title: "PQ Signatures", desc: "ML-DSA-65 in every artifact" },
            ].map((f) => (
              <div key={f.title} className="flex items-start gap-2">
                <span className="text-base mt-0.5">{f.icon}</span>
                <div>
                  <p className="text-xs font-semibold text-white">{f.title}</p>
                  <p className="text-[11px] text-gray-500">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
