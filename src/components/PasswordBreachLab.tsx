import React, { useState } from 'react';
import { 
  KeyRound, 
  Eye, 
  EyeOff, 
  Sparkles, 
  DatabaseZap, 
  Search, 
  CheckCircle2, 
  XCircle, 
  Copy, 
  Check, 
  ShieldAlert, 
  Info,
  Layers,
  Lock
} from 'lucide-react';
import { analyzePassword, generateSecurePassword, generatePassphrase } from '../utils/cryptoUtils';
import { MOCK_BREACH_DATABASE } from '../data/mockSecurityData';
import { BreachRecord } from '../types/security';

export const PasswordBreachLab: React.FC = () => {
  // Password Analyzer State
  const [password, setPassword] = useState<string>('P@ssw0rd2026!');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const analysis = analyzePassword(password);

  // Generator State
  const [genMode, setGenMode] = useState<'chars' | 'passphrase'>('chars');
  const [genLength, setGenLength] = useState<number>(16);
  const [useUpper, setUseUpper] = useState<boolean>(true);
  const [useLower, setUseLower] = useState<boolean>(true);
  const [useNumbers, setUseNumbers] = useState<boolean>(true);
  const [useSymbols, setUseSymbols] = useState<boolean>(true);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Dark Web Breach Search State
  const [breachEmail, setBreachEmail] = useState<string>('admin@company.com');
  const [isSearchingBreach, setIsSearchingBreach] = useState<boolean>(false);
  const [breachResult, setBreachResult] = useState<BreachRecord | null>(null);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleGenerate = () => {
    if (genMode === 'chars') {
      const newPass = generateSecurePassword({
        length: genLength,
        useUpper,
        useLower,
        useNumbers,
        useSymbols,
        avoidAmbiguous: true
      });
      setPassword(newPass);
    } else {
      const newPhrase = generatePassphrase(4);
      setPassword(newPhrase);
    }
  };

  const handleBreachSearch = () => {
    const input = breachEmail.trim().toLowerCase();
    if (!input) return;

    setIsSearchingBreach(true);
    setBreachResult(null);

    setTimeout(() => {
      setIsSearchingBreach(false);
      let matchedBreaches = MOCK_BREACH_DATABASE['pwned'] || [];

      if (input.includes('admin') || input.includes('corp') || input.includes('company')) {
        matchedBreaches = [...(MOCK_BREACH_DATABASE['admin'] || []), ...(MOCK_BREACH_DATABASE['pwned'] || [])];
      } else if (input.includes('clean') || input.includes('secure') || input.includes('safe')) {
        matchedBreaches = [];
      } else if (input.includes('test')) {
        matchedBreaches = MOCK_BREACH_DATABASE['test'] || [];
      }

      setBreachResult({
        email: breachEmail,
        isBreached: matchedBreaches.length > 0,
        breaches: matchedBreaches,
        checkedAt: new Date().toLocaleTimeString()
      });
    }, 700);
  };

  const getScoreColor = () => {
    switch (analysis.classification) {
      case 'CRYPTO_STRONG':
        return { text: 'text-[#00ff88]', bg: 'bg-[#00ff88]', label: 'CRYPTO-STRONG' };
      case 'STRONG':
        return { text: 'text-cyan-400', bg: 'bg-cyan-400', label: 'STRONG' };
      case 'MODERATE':
        return { text: 'text-[#ffb700]', bg: 'bg-[#ffb700]', label: 'MODERATE' };
      case 'WEAK':
      case 'VERY_WEAK':
      default:
        return { text: 'text-[#ff0055]', bg: 'bg-[#ff0055]', label: 'WEAK' };
    }
  };

  const scoreColor = getScoreColor();

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Cryptographic Password & Entropy Evaluator */}
        <div className="lg:col-span-7 bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 space-y-6 shadow-xl">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <KeyRound className="w-4 h-4" />
              <span>Cryptographic Resilience Engine</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Password Strength & Entropy Analyzer
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 leading-relaxed">
              Calculates Shannon information entropy and benchmarks crack time against multi-GPU hashcat dictionary and brute-force clusters.
            </p>
          </div>

          <div className="space-y-4">
            {/* Input with Show/Hide & Copy */}
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password to evaluate..."
                className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-xl px-4 py-3.5 pr-24 text-sm text-white font-mono focus:outline-none transition-all"
              />
              <div className="absolute right-3 top-3 flex items-center space-x-1.5">
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => handleCopy(password)}
                  className="p-1.5 text-slate-400 hover:text-cyan-400 rounded-lg hover:bg-slate-800 transition-colors"
                  title="Copy password"
                >
                  {copiedText === password ? (
                    <Check className="w-4 h-4 text-[#00ff88]" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Strength Bar */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-slate-400">CRYPTOGRAPHIC RESISTANCE</span>
                <span className={`font-bold ${scoreColor.text}`}>{scoreColor.label} ({analysis.score}/100)</span>
              </div>
              <div className="w-full bg-slate-900 h-2.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${scoreColor.bg}`}
                  style={{ width: `${analysis.score}%` }}
                ></div>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-3 gap-3 pt-1">
              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800 text-center">
                <span className="text-[11px] text-slate-400 block font-mono">Crack Resistance</span>
                <span className="text-xs sm:text-sm font-bold font-mono text-white mt-0.5 block truncate">
                  {analysis.crackTimeText}
                </span>
              </div>
              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800 text-center">
                <span className="text-[11px] text-slate-400 block font-mono">Shannon Entropy</span>
                <span className="text-xs sm:text-sm font-bold font-mono text-cyan-400 mt-0.5 block">
                  {analysis.entropy} bits
                </span>
              </div>
              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800 text-center">
                <span className="text-[11px] text-slate-400 block font-mono">Length</span>
                <span className="text-xs sm:text-sm font-bold font-mono text-white mt-0.5 block">
                  {analysis.length} chars
                </span>
              </div>
            </div>

            {/* Requirements Checklist */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono pt-2">
              <div className={`flex items-center space-x-2 ${analysis.rules.minLength ? 'text-[#00ff88]' : 'text-slate-500'}`}>
                {analysis.rules.minLength ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>At least 12 characters ({analysis.length}/12)</span>
              </div>
              <div className={`flex items-center space-x-2 ${analysis.rules.hasNumber ? 'text-[#00ff88]' : 'text-slate-500'}`}>
                {analysis.rules.hasNumber ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>Contains Numeric Digits (0-9)</span>
              </div>
              <div className={`flex items-center space-x-2 ${analysis.rules.hasSymbol ? 'text-[#00ff88]' : 'text-slate-500'}`}>
                {analysis.rules.hasSymbol ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>Contains Special Symbols (!@#$)</span>
              </div>
              <div className={`flex items-center space-x-2 ${analysis.rules.hasMixedCase ? 'text-[#00ff88]' : 'text-slate-500'}`}>
                {analysis.rules.hasMixedCase ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                <span>Mixed Upper & Lowercase Letters</span>
              </div>
            </div>

            {/* Suggestions */}
            {analysis.suggestions.length > 0 && (
              <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/80 text-xs font-mono text-slate-300 space-y-1">
                <span className="text-cyan-400 font-bold block mb-1">NIST 800-63B GUIDANCE:</span>
                {analysis.suggestions.map((sug, i) => (
                  <p key={i} className="text-slate-400">&bull; {sug}</p>
                ))}
              </div>
            )}

            {/* High-Entropy Generator Controls */}
            <div className="pt-4 border-t border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-300 font-bold flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  <span>High-Entropy Generator</span>
                </span>
                <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-[11px] font-mono">
                  <button
                    onClick={() => setGenMode('chars')}
                    className={`px-2 py-0.5 rounded transition-all ${
                      genMode === 'chars' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400'
                    }`}
                  >
                    Random Chars
                  </button>
                  <button
                    onClick={() => setGenMode('passphrase')}
                    className={`px-2 py-0.5 rounded transition-all ${
                      genMode === 'passphrase' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400'
                    }`}
                  >
                    Diceware Passphrase
                  </button>
                </div>
              </div>

              {genMode === 'chars' && (
                <div className="space-y-3 bg-slate-900/40 p-3.5 rounded-xl border border-slate-800 text-xs font-mono">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Length: {genLength} characters</span>
                    <input
                      type="range"
                      min="10"
                      max="48"
                      value={genLength}
                      onChange={(e) => setGenLength(Number(e.target.value))}
                      className="w-32 accent-cyan-400"
                    />
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-slate-300 text-[11px]">
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={useUpper}
                        onChange={(e) => setUseUpper(e.target.checked)}
                        className="rounded accent-cyan-400"
                      />
                      <span>A-Z</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={useLower}
                        onChange={(e) => setUseLower(e.target.checked)}
                        className="rounded accent-cyan-400"
                      />
                      <span>a-z</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={useNumbers}
                        onChange={(e) => setUseNumbers(e.target.checked)}
                        className="rounded accent-cyan-400"
                      />
                      <span>0-9</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={useSymbols}
                        onChange={(e) => setUseSymbols(e.target.checked)}
                        className="rounded accent-cyan-400"
                      />
                      <span>!@#$</span>
                    </label>
                  </div>
                </div>
              )}

              <button
                onClick={handleGenerate}
                className="w-full py-3 bg-[#7000ff]/20 hover:bg-[#7000ff]/30 border border-[#7000ff]/50 text-[#c084fc] font-semibold rounded-xl text-xs sm:text-sm transition-all flex items-center justify-center space-x-2"
              >
                <Sparkles className="w-4 h-4 text-[#c084fc]" />
                <span>
                  {genMode === 'chars' ? 'Generate Cryptographic Password' : 'Generate Memorable Diceware Passphrase'}
                </span>
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Dark Web Data Breach Simulator */}
        <div className="lg:col-span-5 bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 space-y-6 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center space-x-2 text-[#ffb700] text-xs font-mono uppercase tracking-wider mb-1">
              <DatabaseZap className="w-4 h-4" />
              <span>Dark Web Leak Repository</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">Data Breach Detection</h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 leading-relaxed">
              Simulate scanning 12+ billion compromised credentials and leaked dark web identity records.
            </p>

            <div className="mt-5 space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
                  EMAIL ADDRESS OR USERNAME
                </label>
                <input
                  type="email"
                  value={breachEmail}
                  onChange={(e) => setBreachEmail(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleBreachSearch()}
                  placeholder="user@example.com"
                  className="w-full bg-slate-900 border border-slate-700 focus:border-[#ffb700] rounded-xl px-4 py-3 text-xs sm:text-sm text-white font-mono focus:outline-none transition-all"
                />
              </div>

              <div className="flex items-center space-x-2">
                <button
                  disabled={isSearchingBreach}
                  onClick={handleBreachSearch}
                  className="flex-1 py-3 bg-[#ffb700]/10 hover:bg-[#ffb700]/20 border border-[#ffb700]/40 text-[#ffb700] font-semibold rounded-xl text-xs sm:text-sm transition-all flex items-center justify-center space-x-2"
                >
                  <Search className="w-4 h-4" />
                  <span>{isSearchingBreach ? 'Searching Dump Catalogs...' : 'Check Breach Archives'}</span>
                </button>
              </div>

              {/* Sample Queries */}
              <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono text-slate-500">
                <span>Presets:</span>
                <button
                  onClick={() => { setBreachEmail('admin@company.com'); }}
                  className="text-slate-400 hover:text-white underline"
                >
                  admin@company.com
                </button>
                <span>&bull;</span>
                <button
                  onClick={() => { setBreachEmail('safe-clean-user@proton.me'); }}
                  className="text-slate-400 hover:text-white underline"
                >
                  safe-clean@proton.me
                </button>
              </div>
            </div>

            {/* Breach Result Feedback Box */}
            {breachResult && (
              <div className="mt-5 space-y-3">
                {breachResult.isBreached ? (
                  <div className="p-4 rounded-xl border border-[#ff0055]/40 bg-[#ff0055]/5 space-y-3 text-xs font-mono">
                    <div className="flex items-center space-x-2 text-[#ff0055] font-bold">
                      <ShieldAlert className="w-5 h-5" />
                      <span>EXPOSED IN {breachResult.breaches.length} MAJOR DATA LEAKS!</span>
                    </div>

                    <p className="text-slate-300">
                      Credentials associated with <strong className="text-white">{breachResult.email}</strong> were identified in historical leaked dumps:
                    </p>

                    <div className="space-y-2 mt-2">
                      {breachResult.breaches.map((b, idx) => (
                        <div key={idx} className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-white">{b.title}</span>
                            <span className="text-slate-500 text-[10px]">{b.breachDate}</span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{b.description}</p>
                          <div className="flex flex-wrap gap-1 pt-1">
                            {b.dataClasses.map((dc, i) => (
                              <span key={i} className="text-[10px] bg-red-950/50 text-red-300 border border-red-800/40 px-1.5 py-0.2 rounded">
                                {dc}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="pt-2 text-[#ffb700] text-[11px]">
                      <strong>Recommended Countermeasure:</strong> Change passwords for matching accounts immediately and activate Hardware Key (FIDO2) or TOTP MFA.
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded-xl border border-[#00ff88]/40 bg-[#00ff88]/5 space-y-2 text-xs font-mono">
                    <div className="flex items-center space-x-2 text-[#00ff88] font-bold">
                      <CheckCircle2 className="w-5 h-5" />
                      <span>NO KNOWN BREACHES IDENTIFIED</span>
                    </div>
                    <p className="text-slate-300">
                      Target account <strong className="text-white">{breachResult.email}</strong> was not found in known public database leak compilations.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-1.5 font-mono">
            <span className="text-slate-200 font-semibold flex items-center space-x-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Zero-Storage Client Privacy Guarantee</span>
            </span>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              We never transmit or store evaluated passwords or email entries. All entropy mathematics and hash evaluations execute entirely inside your local browser sandbox.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
