import React, { useState } from 'react';
import { 
  Link as LinkIcon, 
  FileUp, 
  Scan, 
  Loader2, 
  ShieldAlert, 
  ShieldCheck, 
  FileCode, 
  Download, 
  CheckCircle2, 
  XCircle, 
  Hash, 
  Clock, 
  ArrowLeft
} from 'lucide-react';
import { ScanReport, ScanEngineResult } from '../types/security';
import { computeSHA256, computeSHA1, pseudoMD5, calculateShannonEntropy } from '../utils/cryptoUtils';
import { SECURITY_SCAN_ENGINES } from '../data/mockSecurityData';

interface ThreatScannerProps {
  initialTarget?: string;
  onIncrementScanCount: () => void;
  onBackToDashboard: () => void;
}

export const ThreatScanner: React.FC<ThreatScannerProps> = ({
  initialTarget = '',
  onIncrementScanCount,
  onBackToDashboard
}) => {
  const [scanMode, setScanMode] = useState<'url' | 'file'>('url');
  const [urlInput, setUrlInput] = useState<string>(initialTarget || 'https://google.com');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<{ sha256: string; sha1: string; md5: string } | null>(null);
  const [fileEntropy, setFileEntropy] = useState<number>(0);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanStatusText, setScanStatusText] = useState<string>('Initializing multi-engine telemetry...');
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [engineFilter, setEngineFilter] = useState<'all' | 'detected' | 'clean'>('all');

  const handleFileDrop = async (file: File) => {
    setSelectedFile(file);
    try {
      const buffer = await file.arrayBuffer();
      const sha256 = await computeSHA256(buffer);
      const sha1 = await computeSHA1(buffer);
      const textSample = new TextDecoder().decode(buffer.slice(0, 1024));
      const md5 = pseudoMD5(sha256);
      const entropy = calculateShannonEntropy(textSample || file.name);

      setFileHash({ sha256, sha1, md5 });
      setFileEntropy(entropy);
    } catch {
      // Fallback
      const sha256 = pseudoMD5(file.name + file.size) + pseudoMD5(file.name);
      setFileHash({ sha256, sha1: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37', md5: pseudoMD5(file.name) });
      setFileEntropy(5.8);
    }
  };

  const executeDiagnosticScan = async (target: string, type: 'url' | 'file') => {
    setIsScanning(true);
    setScanProgress(5);
    setScanReport(null);
    setScanStatusText('Querying global threat intelligence & blocklist mirrors...');

    const lower = target.toLowerCase();
    const isRisky = 
      lower.includes('crypto') || 
      lower.includes('.xyz') || 
      lower.includes('.top') || 
      lower.includes('winner') || 
      lower.includes('exe') || 
      lower.includes('drop') || 
      lower.includes('payload') ||
      lower.includes('temp-site') ||
      lower.includes('paypaI') ||
      lower.includes('agenttesla');

    let current = 5;
    const interval = setInterval(() => {
      current += 20;
      if (current === 25) {
        setScanStatusText('Decompiling bytecode & inspecting heuristic entropy...');
      } else if (current === 65) {
        setScanStatusText('Evaluating TLS certificate chain & domain reputation score...');
      } else if (current === 85) {
        setScanStatusText('Cross-referencing 16 antimalware engine signature feeds...');
      }

      setScanProgress(Math.min(current, 95));

      if (current >= 100) {
        clearInterval(interval);
        finalizeReport(target, type, isRisky);
      }
    }, 280);
  };

  const finalizeReport = async (target: string, type: 'url' | 'file', isRisky: boolean) => {
    setScanProgress(100);
    setIsScanning(false);
    onIncrementScanCount();

    const engineResults: ScanEngineResult[] = SECURITY_SCAN_ENGINES.map((engine, idx) => {
      let detected = false;
      let result = 'Clean';

      if (isRisky) {
        // Flag in 12 of the 16 engines if risky
        detected = idx % 5 !== 3;
        result = detected ? (idx % 2 === 0 ? 'Trojan.Heuristic.Gen' : 'Phishing.DeceptiveDomain') : 'Clean';
      }

      return {
        engine,
        category: idx < 6 ? 'antivirus' : idx < 12 ? 'threat_intel' : 'heuristics',
        detected,
        result,
        updateTime: 'Latest (0 min ago)'
      };
    });

    const hits = engineResults.filter(e => e.detected).length;
    const totalEngines = engineResults.length;

    let targetSha256 = fileHash?.sha256;
    if (!targetSha256) {
      targetSha256 = await computeSHA256(target);
    }

    const report: ScanReport = {
      id: `SCAN-${Date.now().toString().slice(-6)}`,
      target,
      type,
      timestamp: new Date().toLocaleTimeString(),
      status: hits > 4 ? 'malicious' : hits > 0 ? 'suspicious' : 'clean',
      threatScore: isRisky ? 88 : 3,
      engineHits: hits,
      totalEngines,
      hashes: {
        sha256: targetSha256,
        md5: fileHash?.md5 || pseudoMD5(target),
        sha1: fileHash?.sha1 || '7110eda4d09e062aa5e4a390b0a572ac0d2c0220'
      },
      details: {
        domainAge: isRisky ? '3 days (Newly Registered)' : '18 years 4 months',
        registrar: isRisky ? 'NameCheap / Anonymous Privacy Shield' : 'MarkMonitor Inc.',
        sslIssuer: isRisky ? 'Insecure / Self-Signed Free CA' : 'GTS CA 1C3 (Google Trust Services)',
        sslValid: !isRisky,
        reputation: isRisky ? 'Flagged Malicious (Poor)' : 'Trusted High Reputation',
        fileType: type === 'file' ? (selectedFile?.type || 'application/octet-stream') : 'text/html; charset=utf-8',
        fileSizeBytes: type === 'file' ? selectedFile?.size : 1420,
        entropy: type === 'file' ? fileEntropy : 4.2,
        heuristicsNotes: isRisky
          ? [
              'High entropy payload pattern detected in file header.',
              'Domain was registered within the past 14 days (common bulletproof hosting tactic).',
              'Obfuscated JavaScript script tags identified attempting DOM token redirection.',
              'Zero reputable inbound backlinks recorded in global DNS telemetry.'
            ]
          : [
              'Valid cryptographic Extended Validation (EV) TLS certificate.',
              'Domain age exceeds standard reputation baseline thresholds (> 5 years).',
              'No match found in active abuse, spam, or phishing blacklists.'
            ]
      },
      engineResults
    };

    setScanReport(report);
  };

  const handleDownloadReport = () => {
    if (!scanReport) return;
    const blob = new Blob([JSON.stringify(scanReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AegisShield_Audit_${scanReport.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredEngineResults = scanReport?.engineResults.filter((e) => {
    if (engineFilter === 'detected') return e.detected;
    if (engineFilter === 'clean') return !e.detected;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <Scan className="w-4 h-4" />
              <span>Multi-Engine Threat Diagnostic Suite</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">URL & File Threat Diagnostics</h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
              Deep heuristic scanning across 16 antimalware engines, cryptographic hash computation (SHA-256), SSL certificate verification, and reputation telemetry.
            </p>
          </div>

          <button
            onClick={onBackToDashboard}
            className="self-start md:self-auto px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs font-mono flex items-center space-x-2 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Dashboard</span>
          </button>
        </div>

        {/* Scan Mode Tabs */}
        <div className="flex border-b border-slate-800 mt-6 mb-6">
          <button
            onClick={() => setScanMode('url')}
            className={`pb-3 px-4 text-xs sm:text-sm font-semibold border-b-2 flex items-center space-x-2 transition-all ${
              scanMode === 'url'
                ? 'border-[#00f0ff] text-[#00f0ff]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <LinkIcon className="w-4 h-4" />
            <span>Scan URL / Web Domain</span>
          </button>

          <button
            onClick={() => setScanMode('file')}
            className={`pb-3 px-4 text-xs sm:text-sm font-semibold border-b-2 flex items-center space-x-2 transition-all ${
              scanMode === 'file'
                ? 'border-[#00f0ff] text-[#00f0ff]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileUp className="w-4 h-4" />
            <span>Scan Local File</span>
          </button>
        </div>

        {/* Tab 1: URL Scanner Form */}
        {scanMode === 'url' && (
          <div className="space-y-4">
            <label className="block text-xs font-mono text-slate-400">
              ENTER DOMAIN OR FULL TARGET URL
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && executeDiagnosticScan(urlInput, 'url')}
                placeholder="e.g. https://secure-login-bank-verify.xyz/login"
                className="flex-grow bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-xl px-4 py-3.5 text-xs sm:text-sm text-white font-mono focus:outline-none transition-all"
              />
              <button
                disabled={isScanning}
                onClick={() => executeDiagnosticScan(urlInput, 'url')}
                className="px-6 py-3.5 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-slate-950 font-bold rounded-xl text-xs sm:text-sm transition-all flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 active:scale-95 cursor-pointer"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4 text-slate-950" />
                    <span>Scan Target</span>
                  </>
                )}
              </button>
            </div>

            {/* Test Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-2">
              <span className="text-xs text-slate-500 font-mono">Test Presets:</span>
              <button
                onClick={() => setUrlInput('https://google.com')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded-lg font-mono transition-colors"
              >
                Safe Domain (Google)
              </button>
              <button
                onClick={() => setUrlInput('http://free-crypto-giveaway-winner.xyz/login')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded-lg font-mono transition-colors"
              >
                Phishing Scam (.xyz)
              </button>
              <button
                onClick={() => setUrlInput('http://malware-download-drop.temp-site.net/payload.exe')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded-lg font-mono transition-colors"
              >
                Malware Drop (.exe)
              </button>
              <button
                onClick={() => setUrlInput('https://c2-beacon.blackcat-alpha.onion.link/api')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded-lg font-mono transition-colors"
              >
                Ransomware C2
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: File Scanner Form */}
        {scanMode === 'file' && (
          <div className="space-y-4">
            <label className="block text-xs font-mono text-slate-400">
              UPLOAD OR DRAG FILE FOR HEURISTIC AUDIT & CLIENT-SIDE HASH
            </label>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  handleFileDrop(e.dataTransfer.files[0]);
                }
              }}
              onClick={() => document.getElementById('scanner-file-picker')?.click()}
              className="border-2 border-dashed border-slate-700 hover:border-cyan-400 rounded-2xl p-8 text-center bg-slate-900/50 hover:bg-slate-900/80 cursor-pointer transition-all group"
            >
              <FileUp className="w-10 h-10 text-slate-500 group-hover:text-cyan-400 mx-auto mb-3 transition-colors" />
              <p className="text-sm font-semibold text-slate-300 group-hover:text-white">
                Click to upload file or drag & drop here
              </p>
              <p className="text-xs text-slate-500 mt-1 font-mono">
                Supports EXE, DLL, ZIP, PDF, DOCX, APK, JS (Calculates SHA-256 via browser crypto)
              </p>
              <input
                type="file"
                id="scanner-file-picker"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileDrop(e.target.files[0]);
                  }
                }}
              />
            </div>

            {selectedFile && (
              <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div className="flex items-center space-x-3">
                  <FileCode className="w-6 h-6 text-cyan-400" />
                  <div>
                    <p className="font-mono text-white text-xs font-bold">{selectedFile.name}</p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      {(selectedFile.size / 1024).toFixed(1)} KB &bull; {selectedFile.type || 'Binary / Raw'}
                      {fileEntropy > 0 && ` &bull; Entropy: ${fileEntropy} bits`}
                    </p>
                  </div>
                </div>

                <button
                  disabled={isScanning}
                  onClick={() => executeDiagnosticScan(selectedFile.name, 'file')}
                  className="px-5 py-2.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-all flex items-center space-x-2"
                >
                  <Scan className="w-3.5 h-3.5" />
                  <span>Execute File Scan</span>
                </button>
              </div>
            )}
          </div>
        )}

        {/* Scan Progress Bar Animation */}
        {isScanning && (
          <div className="mt-8 space-y-3 bg-slate-900/90 p-6 rounded-xl border border-slate-800 relative overflow-hidden shadow-inner">
            <div className="scanner-line"></div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-cyan-400 flex items-center space-x-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>{scanStatusText}</span>
              </span>
              <span className="text-slate-300 font-bold">{scanProgress}%</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-400 via-[#00f0ff] to-[#7000ff] h-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <div className="text-[11px] font-mono text-slate-500 grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
              <div>SSL Audit: <span className="text-slate-300">Processing...</span></div>
              <div>Blacklist Check: <span className="text-slate-300">Active</span></div>
              <div>Bytecode Entropy: <span className="text-slate-300">Inspecting</span></div>
              <div>Sandbox Sandbox: <span className="text-slate-300">Simulating</span></div>
            </div>
          </div>
        )}

        {/* Scan Results Card */}
        {scanReport && (
          <div className="mt-8 space-y-6">
            <div className={`p-6 rounded-xl border transition-all ${
              scanReport.status === 'malicious'
                ? 'border-[#ff0055]/40 bg-[#ff0055]/5'
                : scanReport.status === 'suspicious'
                ? 'border-[#ffb700]/40 bg-[#ffb700]/5'
                : 'border-[#00ff88]/40 bg-[#00ff88]/5'
            }`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                <div className="flex items-center space-x-3.5">
                  {scanReport.status === 'clean' ? (
                    <div className="p-3 rounded-xl bg-[#00ff88]/10 text-[#00ff88]">
                      <ShieldCheck className="w-8 h-8" />
                    </div>
                  ) : (
                    <div className="p-3 rounded-xl bg-[#ff0055]/10 text-[#ff0055]">
                      <ShieldAlert className="w-8 h-8" />
                    </div>
                  )}
                  <div>
                    <h3 className="font-extrabold text-lg sm:text-xl text-white">
                      {scanReport.status === 'clean'
                        ? 'Target Verified Safe & Clean'
                        : 'Malicious Signature Threat Detected!'}
                    </h3>
                    <p className={`text-xs font-mono font-semibold ${
                      scanReport.status === 'clean' ? 'text-[#00ff88]' : 'text-[#ff0055]'
                    }`}>
                      {scanReport.status === 'clean'
                        ? '0 / 16 Security engines flagged this target'
                        : `${scanReport.engineHits} / ${scanReport.totalEngines} Security engines flagged this target as dangerous`}
                    </p>
                  </div>
                </div>

                <button
                  onClick={handleDownloadReport}
                  className="px-4 py-2 bg-slate-900 border border-slate-700 hover:border-cyan-400 text-slate-200 text-xs font-mono font-semibold rounded-lg flex items-center space-x-2 transition-colors self-start sm:self-auto"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Export JSON Report</span>
                </button>
              </div>

              {/* Target Metadata & Cryptographic Hashes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 font-mono text-xs">
                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-cyan-400 font-semibold mb-2">
                    <Hash className="w-4 h-4" />
                    <span>Cryptographic Fingerprints</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">SHA-256</span>
                    <span className="text-slate-200 break-all select-all">{scanReport.hashes?.sha256}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">MD5</span>
                    <span className="text-slate-300 break-all select-all">{scanReport.hashes?.md5}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">SHA-1</span>
                    <span className="text-slate-400 break-all select-all">{scanReport.hashes?.sha1}</span>
                  </div>
                </div>

                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-cyan-400 font-semibold mb-2">
                    <Clock className="w-4 h-4" />
                    <span>Telemetry & Heuristics</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Domain / File Age:</span>
                    <span className="text-slate-200 font-semibold">{scanReport.details.domainAge}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Registrar / Provider:</span>
                    <span className="text-slate-200">{scanReport.details.registrar}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">TLS Certificate:</span>
                    <span className={scanReport.details.sslValid ? 'text-[#00ff88]' : 'text-[#ff0055]'}>
                      {scanReport.details.sslIssuer}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Reputation Score:</span>
                    <span className={scanReport.status === 'clean' ? 'text-[#00ff88]' : 'text-[#ff0055]'}>
                      {scanReport.details.reputation}
                    </span>
                  </div>
                </div>
              </div>

              {/* Heuristics Bullet Points */}
              <div className="mt-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800 text-xs font-mono space-y-1.5">
                <span className="text-slate-400 font-bold block mb-1">DETECTION REASONING & HEURISTICS:</span>
                {scanReport.details.heuristicsNotes.map((note, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-slate-300">
                    <span className="text-cyan-400">&bull;</span>
                    <span>{note}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Antimalware Engine Breakdown Table */}
            <div className="bg-slate-900/90 rounded-xl border border-slate-800 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div className="flex items-center space-x-2">
                  <span className="text-white font-bold text-sm">Security Engine Detections</span>
                  <span className="text-xs font-mono text-slate-400">({scanReport.totalEngines} engines)</span>
                </div>

                <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-mono">
                  {(['all', 'detected', 'clean'] as const).map((mode) => (
                    <button
                      key={mode}
                      onClick={() => setEngineFilter(mode)}
                      className={`px-3 py-1 rounded-md capitalize transition-all ${
                        engineFilter === mode
                          ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {mode}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                {filteredEngineResults?.map((engine, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border flex items-center justify-between transition-all ${
                      engine.detected
                        ? 'bg-[#ff0055]/5 border-[#ff0055]/20'
                        : 'bg-slate-950/60 border-slate-800'
                    }`}
                  >
                    <span className="text-slate-200 font-semibold">{engine.engine}</span>
                    <div className="flex items-center space-x-1.5">
                      {engine.detected ? (
                        <>
                          <XCircle className="w-4 h-4 text-[#ff0055]" />
                          <span className="text-[#ff0055] font-bold">{engine.result}</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />
                          <span className="text-[#00ff88]">Clean</span>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
