import React, { useState } from 'react';
import { 
  BookOpen, 
  Fingerprint, 
  WifiOff, 
  HardDrive, 
  ShieldAlert, 
  CheckSquare, 
  Square, 
  Download, 
  CheckCircle2, 
  Wrench,
  Sparkles
} from 'lucide-react';
import { DEFENSE_GUIDES } from '../data/mockSecurityData';

export const DefenseVault: React.FC = () => {
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(
    new Set(['GUIDE-MFA-0', 'GUIDE-WIFI-0', 'GUIDE-PATCH-0'])
  );

  const totalSteps = DEFENSE_GUIDES.reduce((acc, guide) => acc + guide.actionableSteps.length, 0);

  const toggleStep = (stepId: string) => {
    setCompletedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(stepId)) {
        next.delete(stepId);
      } else {
        next.add(stepId);
      }
      return next;
    });
  };

  const getGuideIcon = (iconName: string) => {
    switch (iconName) {
      case 'fingerprint':
        return <Fingerprint className="w-6 h-6 text-cyan-400" />;
      case 'wifi-off':
        return <WifiOff className="w-6 h-6 text-[#a855f7]" />;
      case 'hard-drive':
        return <HardDrive className="w-6 h-6 text-[#00ff88]" />;
      case 'shield-alert':
      default:
        return <ShieldAlert className="w-6 h-6 text-[#ffb700]" />;
    }
  };

  const handleExportChecklist = () => {
    let md = '# AegisShield Personal Cybersecurity Hardening Audit\n';
    md += `*Generated: ${new Date().toLocaleString()}*\n\n`;
    md += `## Hardening Score: ${completedSteps.size} of ${totalSteps} Completed (${Math.round((completedSteps.size / totalSteps) * 100)}%)\n\n`;

    DEFENSE_GUIDES.forEach((guide) => {
      md += `### ${guide.title} [Priority: ${guide.priority}]\n`;
      md += `${guide.summary}\n\n`;
      guide.actionableSteps.forEach((step, idx) => {
        const stepKey = `${guide.id}-${idx}`;
        const checked = completedSteps.has(stepKey) ? 'x' : ' ';
        md += `- [${checked}] ${step}\n`;
      });
      md += `\n**Recommended Tooling:** ${guide.toolsRecommended.join(', ')}\n\n---\n\n`;
    });

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AegisShield_Hardening_Checklist_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const progressPercent = Math.round((completedSteps.size / totalSteps) * 100);

  return (
    <div className="space-y-6">
      <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <BookOpen className="w-4 h-4" />
              <span>Interactive Defense Knowledge Vault</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Cybersecurity Hardening & Best Practices Vault
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
              Actionable, step-by-step countermeasure protocols to systematically immunize endpoints against credential stuffing, ransomware, and surveillance.
            </p>
          </div>

          <button
            onClick={handleExportChecklist}
            className="px-4 py-2.5 bg-slate-900 border border-slate-700 hover:border-cyan-400 text-slate-200 text-xs font-mono font-semibold rounded-xl flex items-center space-x-2 transition-colors self-start md:self-auto shadow-md"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export Markdown Checklist</span>
          </button>
        </div>

        {/* Global Progress Bar */}
        <div className="mt-6 bg-slate-900/80 p-4 rounded-xl border border-slate-800 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-slate-300 font-bold flex items-center space-x-1.5">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Endpoint Hardening Implementation Progress</span>
            </span>
            <span className="text-cyan-400 font-bold">
              {completedSteps.size} / {totalSteps} Tasks Completed ({progressPercent}%)
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-gradient-to-r from-cyan-400 via-[#00f0ff] to-[#00ff88] h-full transition-all duration-500 rounded-full"
              style={{ width: `${progressPercent}%` }}
            ></div>
          </div>
        </div>

        {/* Guides Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
          {DEFENSE_GUIDES.map((guide) => (
            <div
              key={guide.id}
              className="bg-slate-900/70 p-6 rounded-2xl border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between space-y-4 shadow-lg group"
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 group-hover:scale-105 transition-transform">
                      {getGuideIcon(guide.iconName)}
                    </div>
                    <div>
                      <h3 className="font-bold text-base text-white">{guide.title}</h3>
                      <span className="text-[11px] font-mono text-slate-400">{guide.category}</span>
                    </div>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 ${
                    guide.priority === 'CRITICAL'
                      ? 'border-[#ff0055]/30 text-[#ff0055] bg-[#ff0055]/10'
                      : 'border-[#ffb700]/30 text-[#ffb700] bg-[#ffb700]/10'
                  }`}>
                    {guide.priority}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {guide.summary}
                </p>

                {/* Interactive Actionable Checklist */}
                <div className="space-y-2 pt-2 border-t border-slate-800 font-mono text-xs">
                  <span className="text-slate-400 font-bold block text-[11px]">ACTIONABLE AUDIT CHECKLIST:</span>
                  {guide.actionableSteps.map((step, idx) => {
                    const stepKey = `${guide.id}-${idx}`;
                    const isChecked = completedSteps.has(stepKey);
                    return (
                      <div
                        key={idx}
                        onClick={() => toggleStep(stepKey)}
                        className={`flex items-start space-x-2.5 p-2 rounded-lg cursor-pointer transition-colors ${
                          isChecked ? 'bg-[#00ff88]/5 text-[#00ff88]' : 'hover:bg-slate-800 text-slate-400'
                        }`}
                      >
                        {isChecked ? (
                          <CheckSquare className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-600 shrink-0 mt-0.5" />
                        )}
                        <span className={`text-[11px] leading-relaxed ${isChecked ? 'line-through text-slate-400' : 'text-slate-200'}`}>
                          {step}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Recommended Tooling Tags */}
              <div className="pt-3 border-t border-slate-800/80">
                <div className="flex items-center space-x-1 text-slate-400 text-[11px] font-mono mb-1.5">
                  <Wrench className="w-3 h-3 text-cyan-400" />
                  <span>Vetted Defense Tooling:</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {guide.toolsRecommended.map((tool, i) => (
                    <span
                      key={i}
                      className="text-[10px] font-mono bg-slate-950 text-slate-300 border border-slate-800 px-2 py-0.5 rounded"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
