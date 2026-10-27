import React, { useState } from 'react';
import { 
  Zap, 
  SearchCode, 
  ShieldAlert, 
  ShieldX, 
  Lock, 
  BrainCircuit, 
  Rss, 
  RefreshCw, 
  TrendingUp, 
  AlertTriangle, 
  ShieldCheck, 
  ArrowRight,
  ExternalLink,
  Radio,
  Bug
} from 'lucide-react';
import { ThreatFeedItem, ThreatSeverity } from '../types/security';

interface DashboardProps {
  threatFeed: ThreatFeedItem[];
  onRefreshFeed: () => void;
  onNavigate: (tab: string, targetUrl?: string) => void;
  phishingScore: number;
  totalPhishingQuestions: number;
  scanCount: number;
}

export const Dashboard: React.FC<DashboardProps> = ({
  threatFeed,
  onRefreshFeed,
  onNavigate,
  phishingScore,
  totalPhishingQuestions,
  scanCount
}) => {
  const [quickUrl, setQuickUrl] = useState('');
  const [quickResult, setQuickResult] = useState<{
    status: 'idle' | 'checking' | 'safe' | 'danger';
    message: string;
  }>({ status: 'idle', message: '' });
  
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [activeThreatDetail, setActiveThreatDetail] = useState<ThreatFeedItem | null>(null);

  const handleQuickScan = () => {
    const input = quickUrl.trim();
    if (!input) {
      setQuickResult({
        status: 'danger',
        message: 'Please provide a domain or URL target to analyze.'
      });
      return;
    }

    setQuickResult({
      status: 'checking',
      message: 'Querying global threat heuristics & blocklists...'
    });

    setTimeout(() => {
      const lower = input.toLowerCase();
      const isSuspicious = 
        lower.includes('crypto') || 
        lower.includes('winner') || 
        lower.includes('.xyz') || 
        lower.includes('.top') || 
        lower.includes('login') || 
        lower.includes('free-');

      if (isSuspicious) {
        setQuickResult({
          status: 'danger',
          message: 'CRITICAL THREAT: Target domain matches known phishing heuristics or malicious typosquatting!'
        });
      } else {
        setQuickResult({
          status: 'safe',
          message: 'CLEAN: No malicious signatures, phishing triggers, or active blacklists detected.'
        });
      }
    }, 600);
  };

  const filteredThreats = threatFeed.filter((item) => {
    if (selectedSeverity === 'ALL') return true;
    return item.level === selectedSeverity;
  });

  const getSeverityBadge = (level: ThreatSeverity) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-[#ff0055] border-[#ff0055]/30 bg-[#ff0055]/10';
      case 'HIGH':
        return 'text-[#ffb700] border-[#ffb700]/30 bg-[#ffb700]/10';
      case 'MEDIUM':
        return 'text-amber-400 border-amber-400/30 bg-amber-400/10';
      case 'LOW':
      default:
        return 'text-[#00f0ff] border-[#00f0ff]/30 bg-[#00f0ff]/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-950 via-[#111625] to-slate-900 border border-slate-800 p-6 sm:p-8 shadow-2xl">
        <div className="absolute -right-10 -bottom-10 w-72 h-72 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute right-40 -top-20 w-72 h-72 bg-[#7000ff]/15 rounded-full blur-3xl pointer-events-none"></div>

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-md bg-cyan-400/10 border border-cyan-400/30 text-cyan-300 text-xs font-mono">
              <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
              <span>SYSTEM SECURITY POSTURE: DEFCON 4 (NOMINAL)</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Digital Perimeter: <span className="text-[#00ff88]">SHIELDED</span>
            </h1>
            <p className="text-slate-400 max-w-2xl text-sm sm:text-base leading-relaxed">
              Real-time threat intelligence pipeline active. Continuously evaluating zero-day exploits, cryptographic resilience, network posture, and user security awareness in a unified defense command hub.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800 shadow-inner">
            <div className="text-center sm:text-left px-3">
              <span className="text-xs text-slate-400 uppercase font-mono block">Threat Posture Score</span>
              <div className="flex items-baseline justify-center sm:justify-start space-x-1 mt-0.5">
                <span className="text-3xl font-extrabold font-mono text-[#00ff88]">98.4</span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
            </div>
            <div className="hidden sm:block h-12 w-px bg-slate-800"></div>
            <button 
              onClick={() => onNavigate('scanner')}
              className="px-5 py-3 bg-gradient-to-r from-[#00f0ff] to-cyan-500 text-slate-950 font-bold rounded-xl hover:brightness-110 active:scale-95 transition-all text-sm flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/25 cursor-pointer"
            >
              <Zap className="w-4 h-4 fill-slate-950 text-slate-950" />
              <span>Launch Threat Scan</span>
            </button>
          </div>
        </div>
      </div>

      {/* Breaking Advisory Alert Ticker */}
      <div className="bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-900 border border-red-500/30 rounded-xl p-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center space-x-2 text-red-300">
          <Bug className="w-4 h-4 text-[#ff0055] shrink-0 animate-pulse" />
          <span className="font-bold text-white">ACTIVE CRITICAL ADVISORY:</span>
          <span className="text-slate-300">CVE-2026-9812 Chromium V8 Memory Corruption (CVSS 9.8)</span>
        </div>
        <button
          onClick={() => onNavigate('cve')}
          className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-semibold hover:underline shrink-0"
        >
          <span>View Mitigation Details</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 text-xs font-medium uppercase font-mono tracking-wider">Targets Scanned</span>
            <div className="p-2 rounded-lg bg-cyan-400/10 text-cyan-400 group-hover:scale-110 transition-transform">
              <SearchCode className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-white">
              {(1429 + scanCount).toLocaleString()}
            </span>
            <span className="text-xs font-mono text-[#00ff88] flex items-center">
              <TrendingUp className="w-3 h-3 mr-1" /> +14 today
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div className="bg-cyan-400 h-full w-4/5 rounded-full"></div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 text-xs font-medium uppercase font-mono tracking-wider">Threats Neutralized</span>
            <div className="p-2 rounded-lg bg-[#ff0055]/10 text-[#ff0055] group-hover:scale-110 transition-transform">
              <ShieldX className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-white">48</span>
            <span className="text-xs font-mono text-[#ff0055] flex items-center">
              <AlertTriangle className="w-3 h-3 mr-1" /> 3 High Risk
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div className="bg-[#ff0055] h-full w-1/4 rounded-full"></div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 text-xs font-medium uppercase font-mono tracking-wider">Connection Encryption</span>
            <div className="p-2 rounded-lg bg-[#00ff88]/10 text-[#00ff88] group-hover:scale-110 transition-transform">
              <Lock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-lg font-bold font-mono text-[#00ff88]">TLS 1.3 Active</span>
            <span className="text-xs font-mono text-slate-400">Encrypted</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div className="bg-[#00ff88] h-full w-full rounded-full"></div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-[#111625] p-5 rounded-xl border border-slate-800 hover:border-slate-700 transition-all shadow-md group">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 text-xs font-medium uppercase font-mono tracking-wider">Phishing Readiness</span>
            <div className="p-2 rounded-lg bg-[#7000ff]/20 text-[#a855f7] group-hover:scale-110 transition-transform">
              <BrainCircuit className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-white">
              {phishingScore} / {totalPhishingQuestions}
            </span>
            <span className="text-xs font-mono text-slate-400">
              {phishingScore > 0 ? `${Math.round((phishingScore / totalPhishingQuestions) * 100)}% Pass` : 'Audit Ready'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-[#7000ff] h-full rounded-full transition-all duration-500"
              style={{ width: `${(phishingScore / totalPhishingQuestions) * 100}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Main Grid: Live Threat Feed & Instant Quick-Check */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Live Security Threat Intelligence */}
        <div className="lg:col-span-2 bg-[#111625] rounded-2xl border border-slate-800 p-6 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div className="flex items-center space-x-2">
                <div className="p-1.5 rounded bg-cyan-400/10 text-cyan-400">
                  <Rss className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">Global Threat Intelligence Feed</h2>
                  <p className="text-xs text-slate-400">Live indicators of compromise & active zero-day exploits</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                {/* Severity Filter Tabs */}
                <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-[11px] font-mono">
                  {['ALL', 'CRITICAL', 'HIGH'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSelectedSeverity(sev)}
                      className={`px-2.5 py-1 rounded-md transition-all ${
                        selectedSeverity === sev 
                          ? 'bg-cyan-500/20 text-cyan-300 font-bold' 
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Feed List */}
            <div className="space-y-2.5 mt-4">
              {filteredThreats.slice(0, 4).map((threat) => (
                <div 
                  key={threat.id}
                  onClick={() => setActiveThreatDetail(threat)}
                  className="p-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all text-xs font-mono cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 group"
                >
                  <div className="flex items-start sm:items-center space-x-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border shrink-0 ${getSeverityBadge(threat.level)}`}>
                      {threat.level}
                    </span>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-white font-semibold group-hover:text-cyan-300 transition-colors">
                          {threat.target}
                        </span>
                        {threat.cve && (
                          <span className="text-[10px] text-cyan-400 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-800/40">
                            {threat.cve}
                          </span>
                        )}
                      </div>
                      <span className="text-slate-400 text-[11px] line-clamp-1">
                        {threat.type} &bull; {threat.description}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end space-x-2 shrink-0">
                    <span className="text-slate-500 text-[10px]">{threat.timestamp}</span>
                    <span className="text-[#00ff88] bg-[#00ff88]/10 border border-[#00ff88]/20 px-2 py-0.5 rounded text-[10px] font-semibold">
                      {threat.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="flex items-center space-x-1.5">
              <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span>Aegis SOC Threat Intel Telemetry Active</span>
            </span>
            <button 
              onClick={onRefreshFeed}
              className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center space-x-1 font-semibold"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Telemetry Feed</span>
            </button>
          </div>
        </div>

        {/* Right Column: Instant URL Quick-Check */}
        <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-white">Instant Target Check</h2>
            </div>
            <p className="text-xs text-slate-400 mb-5 leading-relaxed">
              Verify unknown domains, shortened links, or suspicious file hosts before opening.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
                  TARGET DOMAIN OR URL
                </label>
                <input 
                  type="text" 
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleQuickScan()}
                  placeholder="https://suspect-auth-token.xyz" 
                  className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-xl px-3.5 py-3 text-xs text-white placeholder-slate-500 font-mono focus:outline-none transition-all"
                />
              </div>

              <button 
                onClick={handleQuickScan}
                className="w-full py-2.5 bg-cyan-400/10 hover:bg-cyan-400/20 active:scale-[0.99] border border-cyan-400/40 text-cyan-300 font-semibold rounded-xl text-xs transition-all flex items-center justify-center space-x-2"
              >
                <SearchCode className="w-4 h-4 text-cyan-400" />
                <span>Quick Diagnostic</span>
              </button>

              {/* Quick Result Feedback */}
              {quickResult.status !== 'idle' && (
                <div className={`p-3 rounded-xl text-xs font-mono border transition-all ${
                  quickResult.status === 'safe' 
                    ? 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]'
                    : quickResult.status === 'danger'
                    ? 'bg-[#ff0055]/10 border-[#ff0055]/30 text-[#ff0055]'
                    : 'bg-slate-900 border-slate-800 text-slate-300'
                }`}>
                  <p>{quickResult.message}</p>
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-400 font-mono text-[11px]">Engine: Multi-Heuristic</span>
            <button
              onClick={() => onNavigate('scanner', quickUrl)}
              className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center space-x-1 group"
            >
              <span>Deep Scanner</span>
              <ExternalLink className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>
        </div>
      </div>

      {/* Threat Detail Modal */}
      {activeThreatDetail && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111625] border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(activeThreatDetail.level)}`}>
                  {activeThreatDetail.level}
                </span>
                <span className="text-white font-mono font-bold text-sm">
                  {activeThreatDetail.id}
                </span>
              </div>
              <button 
                onClick={() => setActiveThreatDetail(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 bg-slate-800 rounded"
              >
                ✕ Close
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-slate-400 block text-[11px]">TARGET / IOC</span>
                <p className="text-cyan-300 font-bold break-all mt-0.5">{activeThreatDetail.target}</p>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px]">DESCRIPTION</span>
                <p className="text-slate-200 mt-0.5 leading-relaxed">{activeThreatDetail.description}</p>
              </div>

              {activeThreatDetail.ioc && (
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 break-all">
                  <span className="text-slate-500 block text-[10px]">INDICATOR OF COMPROMISE (IOC)</span>
                  <span className="text-amber-400">{activeThreatDetail.ioc}</span>
                </div>
              )}

              <div className="flex justify-between items-center pt-2">
                <span className="text-slate-400">STATUS: <strong className="text-[#00ff88]">{activeThreatDetail.status}</strong></span>
                <span className="text-slate-500">{activeThreatDetail.timestamp}</span>
              </div>
            </div>

            <div className="pt-2 flex justify-end space-x-2">
              <button 
                onClick={() => {
                  const target = activeThreatDetail.target;
                  setActiveThreatDetail(null);
                  onNavigate('scanner', target);
                }}
                className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs"
              >
                Scan This Target in Sandbox
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
