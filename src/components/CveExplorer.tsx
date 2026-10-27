import React, { useState } from 'react';
import { 
  Bug, 
  Search, 
  AlertTriangle, 
  Copy, 
  Check, 
  ExternalLink, 
  ShieldCheck, 
  Calendar,
  Layers
} from 'lucide-react';
import { CVE_DATABASE } from '../data/mockSecurityData';
import { CVEItem, ThreatSeverity } from '../types/security';

export const CveExplorer: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copiedCve, setCopiedCve] = useState<string | null>(null);

  const handleCopy = (cveId: string) => {
    navigator.clipboard.writeText(cveId);
    setCopiedCve(cveId);
    setTimeout(() => setCopiedCve(null), 2000);
  };

  const filteredCves = CVE_DATABASE.filter((cve) => {
    const matchesSearch = 
      cve.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cve.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cve.affectedProduct.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cve.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || cve.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const getCvssBadge = (score: number) => {
    if (score >= 9.0) return 'text-[#ff0055] border-[#ff0055]/30 bg-[#ff0055]/10';
    if (score >= 7.0) return 'text-[#ffb700] border-[#ffb700]/30 bg-[#ffb700]/10';
    if (score >= 4.0) return 'text-amber-400 border-amber-400/30 bg-amber-400/10';
    return 'text-cyan-400 border-cyan-400/30 bg-cyan-400/10';
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <Bug className="w-4 h-4" />
              <span>National Vulnerability Database Telemetry</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              CVE & Zero-Day Threat Advisory Explorer
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
              Query Common Vulnerabilities and Exposures (CVE), evaluate CVSS v3.1 vector severity, and obtain immediate mitigation countermeasures.
            </p>
          </div>
        </div>

        {/* Search & Filter Toolbar */}
        <div className="flex flex-col sm:flex-row gap-3 mt-6">
          <div className="relative flex-grow">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search CVE ID, affected software, or keywords (e.g. Chrome, OpenSSL, Linux)..."
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-xl pl-10 pr-4 py-3 text-xs sm:text-sm text-white font-mono focus:outline-none transition-all"
            />
          </div>

          <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono shrink-0">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 rounded-lg capitalize transition-all ${
                  severityFilter === sev
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* CVE Cards List */}
        <div className="mt-6 space-y-4">
          {filteredCves.length === 0 ? (
            <div className="text-center py-12 bg-slate-900/50 rounded-xl border border-slate-800 text-slate-400 font-mono text-xs">
              No matching CVE vulnerability advisories located for "{searchQuery}".
            </div>
          ) : (
            filteredCves.map((cve) => (
              <div
                key={cve.id}
                className="bg-slate-900/70 p-5 sm:p-6 rounded-2xl border border-slate-800 hover:border-slate-700 transition-all space-y-3 font-mono shadow-md"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getCvssBadge(cve.cvss)}`}>
                      CVSS {cve.cvss} ({cve.severity})
                    </span>
                    <span className="text-base font-bold text-white tracking-tight">{cve.id}</span>
                    <button
                      onClick={() => handleCopy(cve.id)}
                      className="p-1 text-slate-500 hover:text-cyan-400 rounded transition-colors"
                      title="Copy CVE ID"
                    >
                      {copiedCve === cve.id ? <Check className="w-3.5 h-3.5 text-[#00ff88]" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <div className="flex items-center space-x-2 text-slate-400 text-xs">
                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                    <span>Disclosed: {cve.publishedDate}</span>
                  </div>
                </div>

                <div>
                  <h3 className="font-bold text-sm text-cyan-300">{cve.title}</h3>
                  <p className="text-xs text-slate-300 font-sans mt-1 leading-relaxed">
                    {cve.description}
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs">
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] block">AFFECTED PRODUCT / PLATFORMS</span>
                    <span className="text-slate-200">{cve.affectedProduct}</span>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] block">ATTACK VECTOR</span>
                    <span className="text-amber-400">{cve.attackVector}</span>
                  </div>
                </div>

                <div className="bg-cyan-950/20 p-3.5 rounded-xl border border-cyan-800/30 text-xs space-y-1">
                  <span className="text-cyan-400 font-bold flex items-center space-x-1.5">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>VENDOR REMEDIATION / PATCH ADVICE:</span>
                  </span>
                  <p className="text-slate-300 font-sans text-xs">
                    {cve.remediation}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
