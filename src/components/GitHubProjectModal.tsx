import React, { useState } from 'react';
import { 
  X, 
  Github, 
  Copy, 
  Check, 
  Terminal, 
  FolderTree, 
  Shield, 
  Cpu, 
  Sparkles,
  ExternalLink
} from 'lucide-react';

interface GitHubProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GitHubProjectModal: React.FC<GitHubProjectModalProps> = ({ isOpen, onClose }) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const cloneCommands = `# 1. Clone the repository
git clone https://github.com/your-username/aegisshield-cyber-defense.git

# 2. Enter project directory
cd aegisshield-cyber-defense

# 3. Install dependencies
npm install

# 4. Start local development server
npm run dev

# 5. Build production bundle
npm run build`;

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-[#111625] border border-slate-700 rounded-2xl max-w-2xl w-full p-6 sm:p-8 space-y-6 shadow-2xl overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-white">
              <Github className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                AegisShield GitHub Project
              </h2>
              <span className="text-xs font-mono text-cyan-400">
                Open-Source Production Security Hub Repository
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Project Description */}
        <div className="space-y-3 text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
          <p>
            <strong>AegisShield</strong> is architected as a modular, open-source cybersecurity intelligence platform. It includes multi-engine threat diagnostics, cryptographic password entropy evaluation, dark web breach simulation, network connection auditing, and an interactive human firewall training lab.
          </p>
        </div>

        {/* Quick Clone & Run Terminal */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 flex items-center space-x-1.5 font-bold">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>QUICKSTART TERMINAL COMMANDS</span>
            </span>
            <button
              onClick={() => handleCopy(cloneCommands, 'clone')}
              className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
            >
              {copiedSection === 'clone' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#00ff88]" />
                  <span className="text-[#00ff88]">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Commands</span>
                </>
              )}
            </button>
          </div>

          <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
            {cloneCommands}
          </pre>
        </div>

        {/* Repository Architecture File Tree */}
        <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
          <div className="flex items-center space-x-2 text-white font-bold pb-2 border-b border-slate-800">
            <FolderTree className="w-4 h-4 text-cyan-400" />
            <span>Repository Directory Structure</span>
          </div>
          <div className="text-slate-400 text-[11px] space-y-1">
            <div>├── <span className="text-cyan-400">.github/workflows/</span> (CI/CD Automated Build & Lint)</div>
            <div>├── <span className="text-cyan-400">src/components/</span> (Dashboard, ThreatScanner, PasswordBreachLab...)</div>
            <div>├── <span className="text-cyan-400">src/utils/</span> (Web Crypto, Shannon Entropy, Network Probes)</div>
            <div>├── <span className="text-cyan-400">src/data/</span> (Threat feeds, CVE catalog, Phishing lab scenarios)</div>
            <div>├── <span className="text-cyan-400">src/types/</span> (Strict TypeScript security interfaces)</div>
            <div>├── <span className="text-white">README.md</span> &bull; <span className="text-white">LICENSE</span> (MIT)</div>
          </div>
        </div>

        {/* Tech Stack Badges */}
        <div className="pt-2 flex flex-wrap gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            ⚛️ React 19
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            🟦 TypeScript
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            🎨 Tailwind CSS v4
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            🔐 Web Crypto API
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            ⚡ Vite
          </span>
        </div>

        <div className="pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-mono font-bold transition-colors"
          >
            Close Window
          </button>
        </div>
      </div>
    </div>
  );
};
