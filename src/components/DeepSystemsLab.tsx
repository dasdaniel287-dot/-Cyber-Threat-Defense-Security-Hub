import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Binary, 
  Terminal, 
  ShieldAlert, 
  Key, 
  Layers, 
  Play, 
  FileCode, 
  Lock, 
  Unlock, 
  Sparkles, 
  Search, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  RotateCcw,
  Sliders,
  Copy,
  Check,
  Zap,
  Flame
} from 'lucide-react';
import { analyzeBinary, createSyntheticPE, BinaryAnalysisResult } from '../utils/binaryParser';
import { compileYaraRule, scanWithYara, YARA_PRESET_RULES, YaraMatch } from '../utils/yaraEngine';
import { 
  encryptAesGcm, 
  decryptAesGcm, 
  generateRsaKeyPair, 
  crackCaesarCipher, 
  calculateIndexOfCoincidence,
  AesEncryptionResult,
  RsaKeyPairPem
} from '../utils/cryptoAdvanced';

export const DeepSystemsLab: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'pe' | 'hex' | 'yara' | 'stack' | 'crypto'>('pe');

  // ================= 1. PE / ELF PARSER STATE =================
  const [binaryData, setBinaryData] = useState<Uint8Array>(createSyntheticPE());
  const [binaryAnalysis, setBinaryAnalysis] = useState<BinaryAnalysisResult>(analyzeBinary(createSyntheticPE().buffer));
  const [customBinaryName, setCustomBinaryName] = useState<string>('sample_windows_amd64.exe');

  const handleBinaryFileUpload = async (file: File) => {
    setCustomBinaryName(file.name);
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    setBinaryData(bytes);
    setBinaryAnalysis(analyzeBinary(buffer));
  };

  const loadSyntheticPE = () => {
    const synth = createSyntheticPE();
    setCustomBinaryName('sample_windows_amd64.exe');
    setBinaryData(synth);
    setBinaryAnalysis(analyzeBinary(synth.buffer));
  };

  // ================= 2. HEX DUMP DISSECTOR STATE =================
  const [hexOffsetStart, setHexOffsetStart] = useState<number>(0);
  const [selectedByteIdx, setSelectedByteIdx] = useState<number | null>(0);

  // ================= 3. YARA COMPILER STATE =================
  const [yaraRuleText, setYaraRuleText] = useState<string>(YARA_PRESET_RULES[0].ruleText);
  const [yaraTargetText, setYaraTargetText] = useState<string>(YARA_PRESET_RULES[0].testPayload);
  const [yaraResult, setYaraResult] = useState<YaraMatch | null>(null);

  const handleRunYara = () => {
    try {
      const parsed = compileYaraRule(yaraRuleText);
      const encoder = new TextEncoder();
      const targetBytes = encoder.encode(yaraTargetText);
      const res = scanWithYara(parsed, targetBytes);
      setYaraResult(res);
    } catch {
      // Fallback
    }
  };

  useEffect(() => {
    handleRunYara();
  }, []);

  // ================= 4. BUFFER OVERFLOW VISUALIZER STATE =================
  const [bufferPayload, setBufferPayload] = useState<string>('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde');
  const [stackCanaryEnabled, setStackCanaryEnabled] = useState<boolean>(true);
  const [aslrEnabled, setAslrEnabled] = useState<boolean>(false);
  const [depEnabled, setDepEnabled] = useState<boolean>(true);

  // 64-bit Stack Frame Model: 32 bytes buffer + 8 bytes canary + 8 bytes saved RBP + 8 bytes return RIP = 56 bytes total
  const BUFFER_SIZE = 32;
  const CANARY_SIZE = 8;
  const RBP_SIZE = 8;
  const RIP_SIZE = 8;

  const payloadBytes = new TextEncoder().encode(bufferPayload);
  const isBufferOverflowed = payloadBytes.length > BUFFER_SIZE;
  const isCanaryCorrupted = stackCanaryEnabled && payloadBytes.length > BUFFER_SIZE;
  const isRbpOverwritten = payloadBytes.length > BUFFER_SIZE + CANARY_SIZE;
  const isRipOverwritten = payloadBytes.length >= BUFFER_SIZE + CANARY_SIZE + RBP_SIZE + 4;

  let exploitStatus: 'SAFE' | 'CANARY_FAIL' | 'CRASH_SEGFAULT' | 'EIP_CONTROL' = 'SAFE';
  if (isCanaryCorrupted) {
    exploitStatus = 'CANARY_FAIL';
  } else if (!stackCanaryEnabled && isRipOverwritten) {
    exploitStatus = 'EIP_CONTROL';
  } else if (isBufferOverflowed) {
    exploitStatus = 'CRASH_SEGFAULT';
  }

  // ================= 5. CRYPTO & CIPHER CRACKER STATE =================
  const [aesPlaintext, setAesPlaintext] = useState<string>('TOP_SECRET_MILITARY_TELEMETRY: TARGET_DEFCON_1');
  const [aesPassphrase, setAesPassphrase] = useState<string>('QuantumShield#2026!');
  const [aesResult, setAesResult] = useState<AesEncryptionResult | null>(null);
  const [aesDecryptedOutput, setAesDecryptedOutput] = useState<string>('');

  const [rsaKeys, setRsaKeys] = useState<RsaKeyPairPem | null>(null);
  const [isGeneratingRsa, setIsGeneratingRsa] = useState<boolean>(false);

  const [caesarCiphertext, setCaesarCiphertext] = useState<string>(
    'KHOOR ZRUOG WKLV LV DQ HQFUBSWHG PHVVDJH XVLQJ FDHVDU FLSKHU DQG QHHGV FUBSWDQDOBVLV'
  );
  const [caesarResults, setCaesarResults] = useState<{ shift: number; plaintext: string; chiSquared: number }[]>([]);
  const [iocScore, setIocScore] = useState<number>(0);

  const handleEncryptAes = async () => {
    const res = await encryptAesGcm(aesPlaintext, aesPassphrase);
    setAesResult(res);
    setAesDecryptedOutput('');
  };

  const handleDecryptAes = async () => {
    if (!aesResult) return;
    try {
      const dec = await decryptAesGcm(
        aesResult.ciphertextHex,
        aesResult.ivHex,
        aesResult.saltHex,
        aesResult.tagHex,
        aesPassphrase
      );
      setAesDecryptedOutput(dec);
    } catch {
      setAesDecryptedOutput('DECRYPTION INTEGRITY FAILED: Authentication tag mismatch (tampering detected)!');
    }
  };

  const handleGenerateRsa = async () => {
    setIsGeneratingRsa(true);
    const { pem } = await generateRsaKeyPair();
    setRsaKeys(pem);
    setIsGeneratingRsa(false);
  };

  const handleCrackCaesar = () => {
    const cracked = crackCaesarCipher(caesarCiphertext);
    setCaesarResults(cracked.slice(0, 5));
    setIocScore(calculateIndexOfCoincidence(caesarCiphertext));
  };

  useEffect(() => {
    handleEncryptAes();
    handleCrackCaesar();
  }, []);

  return (
    <div className="space-y-6">
      <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <Cpu className="w-4 h-4 text-cyan-400 animate-pulse" />
              <span>Advanced Computer Science & Systems Engineering Lab</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Deep Systems, Binary & Cryptanalysis Operations
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
              Low-level reverse engineering suite: Portable Executable (PE) & ELF parser, Shannon entropy mapping, YARA pattern compiler, x86_64 stack frame exploit visualizer, and hardware-accelerated cryptanalysis.
            </p>
          </div>

          <div className="flex items-center space-x-2 bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-ping"></span>
            <span className="text-slate-300">Ring-0 Dissector: <strong className="text-[#00ff88]">READY</strong></span>
          </div>
        </div>

        {/* Sub-Navigation Tabs */}
        <div className="flex flex-wrap gap-2 pt-6 pb-2">
          {[
            { id: 'pe', label: 'PE / ELF Binary Header Parser', icon: Binary },
            { id: 'hex', label: 'Interactive Hex Dump Dissector', icon: FileCode },
            { id: 'yara', label: 'YARA Rule Compiler & Engine', icon: Search },
            { id: 'stack', label: 'x86_64 Stack Frame & Buffer Overflow', icon: Flame },
            { id: 'crypto', label: 'Hardware Cryptography & Cipher Solver', icon: Lock }
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id as typeof activeSubTab)}
                className={`px-3.5 py-2.5 rounded-xl text-xs font-mono font-semibold transition-all flex items-center space-x-2 ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 shadow-sm shadow-cyan-500/10'
                    : 'bg-slate-900/80 text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* ================= TAB 1: PE / ELF PARSER ================= */}
        {activeSubTab === 'pe' && (
          <div className="space-y-6 mt-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div className="flex items-center space-x-3">
                <Binary className="w-6 h-6 text-cyan-400" />
                <div>
                  <span className="text-xs font-mono text-slate-500">Active Loaded Binary:</span>
                  <p className="text-sm font-mono font-bold text-white">{customBinaryName}</p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={loadSyntheticPE}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono"
                >
                  Load Synthetic x64 PE
                </button>
                <label className="px-3 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs font-mono cursor-pointer transition-colors">
                  Upload Custom Executable
                  <input
                    type="file"
                    className="hidden"
                    onChange={(e) => e.target.files?.[0] && handleBinaryFileUpload(e.target.files[0])}
                  />
                </label>
              </div>
            </div>

            {/* Header Telemetry Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">FORMAT ARCHITECTURE</span>
                <span className="text-cyan-300 font-bold block">
                  {binaryAnalysis.peInfo?.format || binaryAnalysis.elfInfo?.format || binaryAnalysis.architecture}
                </span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">ENTRY POINT ADDRESS</span>
                <span className="text-[#00ff88] font-bold block">
                  {binaryAnalysis.peInfo?.entryPoint || binaryAnalysis.elfInfo?.entryPoint || '0x00000000'}
                </span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">GLOBAL SHANNON ENTROPY</span>
                <span className={`font-bold block ${binaryAnalysis.entropy > 7.0 ? 'text-[#ff0055]' : 'text-cyan-300'}`}>
                  {binaryAnalysis.entropy} / 8.0 bits
                </span>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">PACKER / CRYPTER STATUS</span>
                <span className={binaryAnalysis.peInfo?.packerDetected ? 'text-[#ff0055] font-bold block' : 'text-[#00ff88] font-bold block'}>
                  {binaryAnalysis.peInfo?.packerDetected || 'Native / Unpacked'}
                </span>
              </div>
            </div>

            {/* Security Mitigation Posture */}
            {binaryAnalysis.peInfo && (
              <div className="bg-slate-900/70 p-4 rounded-xl border border-slate-800 space-y-2 font-mono text-xs">
                <span className="text-white font-bold block mb-1">BINARY MITIGATION FLAGS (IMAGE_DLLCHARACTERISTICS):</span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className={`p-2 rounded-lg border flex items-center justify-between ${binaryAnalysis.peInfo.securityFeatures.aslr ? 'bg-[#00ff88]/5 border-[#00ff88]/20 text-[#00ff88]' : 'bg-red-950/20 border-red-800 text-red-400'}`}>
                    <span>ASLR (PIE Dynamic Base)</span>
                    <span>{binaryAnalysis.peInfo.securityFeatures.aslr ? '✓' : '✗'}</span>
                  </div>
                  <div className={`p-2 rounded-lg border flex items-center justify-between ${binaryAnalysis.peInfo.securityFeatures.dep ? 'bg-[#00ff88]/5 border-[#00ff88]/20 text-[#00ff88]' : 'bg-red-950/20 border-red-800 text-red-400'}`}>
                    <span>DEP / NX (No-Execute)</span>
                    <span>{binaryAnalysis.peInfo.securityFeatures.dep ? '✓' : '✗'}</span>
                  </div>
                  <div className={`p-2 rounded-lg border flex items-center justify-between ${binaryAnalysis.peInfo.securityFeatures.cfg ? 'bg-[#00ff88]/5 border-[#00ff88]/20 text-[#00ff88]' : 'bg-slate-950 border-slate-800 text-slate-400'}`}>
                    <span>CFG (Control Flow Guard)</span>
                    <span>{binaryAnalysis.peInfo.securityFeatures.cfg ? '✓' : '✗'}</span>
                  </div>
                  <div className={`p-2 rounded-lg border flex items-center justify-between ${binaryAnalysis.peInfo.securityFeatures.seh ? 'bg-[#00ff88]/5 border-[#00ff88]/20 text-[#00ff88]' : 'bg-slate-950 border-slate-800 text-slate-400'}`}>
                    <span>Structured Exception (SEH)</span>
                    <span>{binaryAnalysis.peInfo.securityFeatures.seh ? '✓' : '✗'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Section Entropy Table & Visual Bar Chart */}
            {binaryAnalysis.peInfo && binaryAnalysis.peInfo.sections.length > 0 && (
              <div className="bg-slate-950 rounded-xl border border-slate-800 p-5 space-y-4 font-mono text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-white font-bold">SECTION HEADERS & SHANNON ENTROPY DISTRIBUTION</span>
                  <span className="text-[11px] text-slate-500">Threshold: &gt; 7.2 indicates packed payload</span>
                </div>

                <div className="space-y-3">
                  {binaryAnalysis.peInfo.sections.map((sec, idx) => (
                    <div key={idx} className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 space-y-2">
                      <div className="flex justify-between items-center text-xs">
                        <div className="flex items-center space-x-2">
                          <span className="text-cyan-400 font-bold">{sec.name}</span>
                          <span className="text-slate-500 text-[10px]">RVA: {sec.virtualAddress}</span>
                          <span className="text-slate-500 text-[10px]">Raw: {sec.rawSize} bytes</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={sec.entropy > 7.1 ? 'text-[#ff0055] font-bold' : 'text-slate-300'}>
                            {sec.entropy} bits
                          </span>
                          {sec.isPacked && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-950 text-red-300 border border-red-800">
                              HIGH ENTROPY / PACKED
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Visual Entropy Bar */}
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${
                            sec.entropy > 7.1 ? 'bg-[#ff0055]' : sec.entropy > 6.0 ? 'bg-amber-400' : 'bg-cyan-400'
                          }`}
                          style={{ width: `${(sec.entropy / 8.0) * 100}%` }}
                        ></div>
                      </div>

                      <div className="text-[10px] text-slate-500 flex flex-wrap gap-1">
                        {sec.characteristics.map((c, i) => (
                          <span key={i} className="bg-slate-950 px-1.5 py-0.2 rounded border border-slate-800 text-slate-400">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB 2: HEX DUMP DISSECTOR ================= */}
        {activeSubTab === 'hex' && (
          <div className="space-y-4 mt-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
              <span className="text-xs font-mono text-slate-400 font-bold">
                CANONICAL 16-BYTE HEXADECIMAL INSPECTOR (Offset &bull; Hex Bytes &bull; ASCII)
              </span>
              <span className="text-xs font-mono text-cyan-400">
                Click any byte to decode data primitives
              </span>
            </div>

            {/* Hex Dump Container */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto max-h-96 select-none shadow-inner">
              <div className="grid grid-cols-1 gap-1 text-[11px] leading-relaxed">
                {Array.from({ length: Math.min(32, Math.ceil(binaryData.length / 16)) }).map((_, rowIdx) => {
                  const offset = rowIdx * 16;
                  const rowSlice = binaryData.slice(offset, offset + 16);
                  return (
                    <div key={rowIdx} className="flex items-center space-x-4 hover:bg-slate-900/60 px-2 py-0.5 rounded">
                      {/* Offset */}
                      <span className="text-slate-500 font-bold select-none">
                        {offset.toString(16).padStart(8, '0').toUpperCase()}
                      </span>

                      {/* Hex Bytes */}
                      <div className="flex space-x-1.5 text-slate-300">
                        {Array.from({ length: 16 }).map((_, colIdx) => {
                          const byteIndex = offset + colIdx;
                          const hasByte = colIdx < rowSlice.length;
                          const byteVal = hasByte ? rowSlice[colIdx] : null;
                          const isSelected = selectedByteIdx === byteIndex;

                          return (
                            <span
                              key={colIdx}
                              onClick={() => hasByte && setSelectedByteIdx(byteIndex)}
                              className={`cursor-pointer px-0.5 rounded transition-colors ${
                                isSelected
                                  ? 'bg-cyan-400 text-slate-950 font-bold'
                                  : byteVal === 0
                                  ? 'text-slate-600 hover:text-white'
                                  : 'hover:bg-slate-800 hover:text-cyan-300'
                              } ${colIdx === 7 ? 'mr-2' : ''}`}
                            >
                              {byteVal !== null ? byteVal.toString(16).padStart(2, '0').toUpperCase() : '  '}
                            </span>
                          );
                        })}
                      </div>

                      {/* ASCII Representation */}
                      <div className="border-l border-slate-800 pl-3 text-cyan-300">
                        {Array.from(rowSlice).map((b, i) => (
                          <span
                            key={i}
                            className={selectedByteIdx === offset + i ? 'bg-cyan-400 text-slate-950 font-bold px-0.5 rounded' : ''}
                          >
                            {b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected Byte Primitive Inspector */}
            {selectedByteIdx !== null && selectedByteIdx < binaryData.length && (
              <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
                <div className="flex justify-between items-center text-cyan-400 font-bold">
                  <span>BYTE DISSECTION INSPECTOR @ OFFSET 0x{selectedByteIdx.toString(16).toUpperCase()}</span>
                  <span className="text-white text-[11px]">Decimal Offset: {selectedByteIdx}</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-1 text-slate-300">
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Hex Value</span>
                    <span className="text-cyan-300 font-bold">
                      0x{binaryData[selectedByteIdx].toString(16).padStart(2, '0').toUpperCase()}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">uint8 (Unsigned)</span>
                    <span className="text-white font-bold">{binaryData[selectedByteIdx]}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">ASCII Glyph</span>
                    <span className="text-[#00ff88] font-bold">
                      {binaryData[selectedByteIdx] >= 32 && binaryData[selectedByteIdx] <= 126
                        ? `'${String.fromCharCode(binaryData[selectedByteIdx])}'`
                        : '(Non-printable)'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Binary 8-Bit</span>
                    <span className="text-amber-400 font-mono text-[11px]">
                      {binaryData[selectedByteIdx].toString(2).padStart(8, '0')}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 col-span-2 sm:col-span-1">
                    <span className="text-slate-500 text-[10px] block">uint16 Little-Endian</span>
                    <span className="text-white">
                      {selectedByteIdx + 1 < binaryData.length
                        ? (binaryData[selectedByteIdx] | (binaryData[selectedByteIdx + 1] << 8))
                        : '--'}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB 3: YARA COMPILER & ENGINE ================= */}
        {activeSubTab === 'yara' && (
          <div className="space-y-6 mt-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block">Signature Compiler</span>
                <h3 className="text-lg font-bold text-white">YARA Rule Syntax Compiler & Memory Scanner</h3>
              </div>

              {/* YARA Presets */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                <span className="text-slate-500">Preset Rules:</span>
                {YARA_PRESET_RULES.map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setYaraRuleText(preset.ruleText);
                      setYaraTargetText(preset.testPayload);
                    }}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-mono text-[11px]"
                  >
                    {preset.name.split('_')[0]}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* YARA Code Editor */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-mono text-slate-400">
                  <span className="flex items-center space-x-1.5">
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>YARA RULE DEFINITION</span>
                  </span>
                </div>
                <textarea
                  value={yaraRuleText}
                  onChange={(e) => setYaraRuleText(e.target.value)}
                  rows={12}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-400 rounded-xl p-4 font-mono text-xs text-cyan-300 leading-relaxed focus:outline-none transition-all shadow-inner"
                  spellCheck={false}
                />
              </div>

              {/* Target Payload Text */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-mono text-slate-400">
                  <span className="flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-[#00ff88]" />
                    <span>TARGET BUFFER / MEMORY DUMP PAYLOAD</span>
                  </span>
                </div>
                <textarea
                  value={yaraTargetText}
                  onChange={(e) => setYaraTargetText(e.target.value)}
                  rows={12}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-400 rounded-xl p-4 font-mono text-xs text-slate-200 leading-relaxed focus:outline-none transition-all shadow-inner"
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="flex justify-between items-center pt-2">
              <span className="text-xs font-mono text-slate-500">
                Engine supports meta, strings ($a="text", $h={'{'}48 89{'}'}, $r=/reg/), condition (any/all/boolean)
              </span>
              <button
                onClick={handleRunYara}
                className="px-6 py-2.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-xl text-xs font-mono flex items-center space-x-2 transition-all shadow-lg shadow-cyan-500/20 active:scale-95 cursor-pointer"
              >
                <Play className="w-4 h-4 fill-slate-950" />
                <span>Compile & Scan Buffer</span>
              </button>
            </div>

            {/* YARA Match Results Output */}
            {yaraResult && (
              <div className={`p-5 rounded-xl border font-mono text-xs space-y-3 ${
                yaraResult.matched ? 'bg-[#ff0055]/10 border-[#ff0055]/30' : 'bg-slate-950 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {yaraResult.matched ? (
                      <>
                        <ShieldAlert className="w-5 h-5 text-[#ff0055]" />
                        <span className="font-bold text-white text-sm">
                          YARA RULE HIT: {yaraResult.ruleName}
                        </span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-[#00ff88]" />
                        <span className="font-bold text-[#00ff88] text-sm">
                          NO SIGNATURE MATCHES DETECTED
                        </span>
                      </>
                    )}
                  </div>
                  <span className="text-slate-500 text-[11px]">Execution: {yaraResult.executionTimeMs} ms</span>
                </div>

                {yaraResult.matched && (
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <span className="text-slate-400 font-bold block text-[11px]">
                      MATCHED PATTERNS ({yaraResult.matchedStrings.length} OCCURRENCES):
                    </span>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {yaraResult.matchedStrings.map((m, idx) => (
                        <div key={idx} className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800 flex justify-between items-center text-[11px]">
                          <div className="flex items-center space-x-2">
                            <span className="text-cyan-400 font-bold">{m.identifier}</span>
                            <span className="text-slate-400">[{m.type}]</span>
                            <span className="text-white font-bold">{m.matchedValue}</span>
                          </div>
                          <span className="text-amber-400 font-bold">{m.offsetHex}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ================= TAB 4: BUFFER OVERFLOW VISUALIZER ================= */}
        {activeSubTab === 'stack' && (
          <div className="space-y-6 mt-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block">Memory Exploit Mechanics</span>
                <h3 className="text-lg font-bold text-white">x86_64 Stack Frame & Buffer Overflow Visualizer</h3>
                <p className="text-xs text-slate-400">Simulates user input overflowing stack buffers into canary, saved RBP, and return RIP addresses.</p>
              </div>

              {/* Mitigation Switches */}
              <div className="flex items-center space-x-3 bg-slate-900 p-2 rounded-xl border border-slate-800 text-xs font-mono">
                <label className="flex items-center space-x-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={stackCanaryEnabled}
                    onChange={(e) => setStackCanaryEnabled(e.target.checked)}
                    className="rounded accent-cyan-400"
                  />
                  <span>Stack Canary</span>
                </label>
                <label className="flex items-center space-x-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={depEnabled}
                    onChange={(e) => setDepEnabled(e.target.checked)}
                    className="rounded accent-cyan-400"
                  />
                  <span>DEP/NX</span>
                </label>
              </div>
            </div>

            {/* Input Payload Controls & Presets */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 font-mono text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-400 font-bold">USER INPUT BUFFER PAYLOAD ({payloadBytes.length} bytes):</span>
                <div className="flex space-x-2">
                  <button
                    onClick={() => setBufferPayload('A'.repeat(16))}
                    className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
                  >
                    Safe Input (16B)
                  </button>
                  <button
                    onClick={() => setBufferPayload('A'.repeat(32))}
                    className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
                  >
                    Exact Fill (32B)
                  </button>
                  <button
                    onClick={() => setBufferPayload('A'.repeat(40))}
                    className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px]"
                  >
                    Smash Canary (40B)
                  </button>
                  <button
                    onClick={() => setBufferPayload('A'.repeat(48) + '\xef\xbe\xad\xde\xef\xbe\xad\xde')}
                    className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 text-[10px]"
                  >
                    Overwrite RIP (0xDEADBEEF)
                  </button>
                </div>
              </div>

              <input
                type="text"
                value={bufferPayload}
                onChange={(e) => setBufferPayload(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none"
              />
            </div>

            {/* Exploit Status Banner */}
            <div className={`p-4 rounded-xl border font-mono text-xs flex items-center space-x-3 ${
              exploitStatus === 'CANARY_FAIL'
                ? 'bg-[#ff0055]/15 border-[#ff0055]/40 text-[#ff0055]'
                : exploitStatus === 'EIP_CONTROL'
                ? 'bg-[#7000ff]/20 border-[#7000ff]/40 text-[#c084fc]'
                : exploitStatus === 'CRASH_SEGFAULT'
                ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                : 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]'
            }`}>
              <ShieldAlert className="w-5 h-5 shrink-0" />
              <div>
                <strong className="block text-sm">
                  {exploitStatus === 'CANARY_FAIL' && 'STACK SMASHING DETECTED: __stack_chk_fail() triggered!'}
                  {exploitStatus === 'EIP_CONTROL' && 'CRITICAL VULNERABILITY: Instruction Pointer (RIP) Successfully Hijacked!'}
                  {exploitStatus === 'CRASH_SEGFAULT' && 'MEMORY CORRUPTION: Segmentation Fault (SIGSEGV) in target function.'}
                  {exploitStatus === 'SAFE' && 'STACK INTEGRITY NOMINAL: Payload fits comfortably within allocated buffer.'}
                </strong>
                <span className="text-[11px] opacity-90">
                  {exploitStatus === 'CANARY_FAIL' && 'The stack guard canary value was altered. The compiler generated canary check halted process before returning.'}
                  {exploitStatus === 'EIP_CONTROL' && 'With stack canary disabled, caller return address was overwritten. CPU attempts jump to attacker address!'}
                  {exploitStatus === 'SAFE' && 'Zero memory boundary violations detected.'}
                </span>
              </div>
            </div>

            {/* Visual Stack Layout Diagram */}
            <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800 font-mono text-xs space-y-4">
              <div className="flex justify-between items-center text-slate-400 text-[11px] pb-2 border-b border-slate-800">
                <span>LOW MEMORY (RSP: 0x7FFFFFFFE100)</span>
                <span>STACK GROWS DOWNWARDS &darr;</span>
                <span>HIGH MEMORY (0x7FFFFFFFE140)</span>
              </div>

              {/* Stack Cells */}
              <div className="grid grid-cols-1 gap-2.5">
                {/* 1. Local Buffer (32 Bytes) */}
                <div className={`p-3 rounded-xl border ${
                  isBufferOverflowed ? 'bg-cyan-950/40 border-cyan-500/40' : 'bg-slate-900 border-slate-800'
                }`}>
                  <div className="flex justify-between items-center text-cyan-400 font-bold mb-1">
                    <span>1. LOCAL STACK BUFFER [char buf[32]]</span>
                    <span>32 Bytes Allocated</span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">
                    Contents: {bufferPayload.slice(0, BUFFER_SIZE) || '(empty)'}
                  </div>
                  <div className="w-full bg-slate-950 h-1.5 rounded-full mt-2 overflow-hidden">
                    <div
                      className="bg-cyan-400 h-full rounded-full"
                      style={{ width: `${Math.min(100, (payloadBytes.length / BUFFER_SIZE) * 100)}%` }}
                    ></div>
                  </div>
                </div>

                {/* 2. Stack Canary (8 Bytes) */}
                <div className={`p-3 rounded-xl border ${
                  !stackCanaryEnabled
                    ? 'bg-slate-950 border-slate-800 text-slate-600'
                    : isCanaryCorrupted
                    ? 'bg-red-950/40 border-red-500 text-red-400'
                    : 'bg-[#00ff88]/5 border-[#00ff88]/30 text-[#00ff88]'
                }`}>
                  <div className="flex justify-between items-center font-bold mb-1">
                    <span>2. STACK GUARD CANARY [__stack_chk_guard]</span>
                    <span>8 Bytes</span>
                  </div>
                  <div className="text-[11px] font-mono">
                    {stackCanaryEnabled ? (
                      isCanaryCorrupted ? (
                        <span className="text-red-400 font-bold">
                          CORRUPTED: 0x{Array.from(payloadBytes.slice(32, 40)).map(b => b.toString(16).padStart(2, '0')).join('')}
                        </span>
                      ) : (
                        <span>INTACT: 0x8974AB00FFE82100 (Contains \x00 terminator)</span>
                      )
                    ) : (
                      <span>DISABLED (Compiled without -fstack-protector)</span>
                    )}
                  </div>
                </div>

                {/* 3. Saved Base Pointer RBP (8 Bytes) */}
                <div className={`p-3 rounded-xl border ${
                  isRbpOverwritten ? 'bg-amber-950/30 border-amber-600/40 text-amber-300' : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}>
                  <div className="flex justify-between items-center font-bold mb-1">
                    <span>3. SAVED FRAME POINTER [%rbp]</span>
                    <span>8 Bytes</span>
                  </div>
                  <div className="text-[11px]">
                    {isRbpOverwritten ? 'CLOBBERED BY OVERFLOW BYTES' : '0x00007FFFFFFFE160 (Valid Caller Stack Base)'}
                  </div>
                </div>

                {/* 4. Return Address RIP (8 Bytes) */}
                <div className={`p-3 rounded-xl border ${
                  isRipOverwritten && !stackCanaryEnabled
                    ? 'bg-[#7000ff]/30 border-[#7000ff] text-purple-300 animate-pulse'
                    : isRipOverwritten
                    ? 'bg-red-950/40 border-red-800 text-red-400'
                    : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}>
                  <div className="flex justify-between items-center font-bold mb-1">
                    <span>4. SAVED RETURN ADDRESS [%rip - INSTRUCTION POINTER]</span>
                    <span>8 Bytes</span>
                  </div>
                  <div className="text-[11px] font-bold">
                    {isRipOverwritten ? (
                      <span className="text-[#c084fc]">
                        HIJACKED VALUE: 0x{Array.from(payloadBytes.slice(48, 56)).map(b => b.toString(16).padStart(2, '0')).join('') || 'DEADBEEF'}
                      </span>
                    ) : (
                      <span className="text-white">0x0000555555555189 (Normal return to main() caller)</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ================= TAB 5: CRYPTO & CIPHER SOLVER ================= */}
        {activeSubTab === 'crypto' && (
          <div className="space-y-6 mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left: Hardware AES-256-GCM */}
              <div className="bg-slate-900/70 p-5 rounded-2xl border border-slate-800 space-y-4 font-mono text-xs">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold">
                  <Lock className="w-4 h-4" />
                  <span>HARDWARE AES-256-GCM (100k PBKDF2 Iterations)</span>
                </div>

                <div className="space-y-2">
                  <label className="text-slate-400 text-[11px]">PLAINTEXT MESSAGE</label>
                  <textarea
                    value={aesPlaintext}
                    onChange={(e) => setAesPlaintext(e.target.value)}
                    rows={2}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-white"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-slate-400 text-[11px]">PASSPHRASE</label>
                  <input
                    type="text"
                    value={aesPassphrase}
                    onChange={(e) => setAesPassphrase(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  />
                </div>

                <div className="flex space-x-2 pt-1">
                  <button
                    onClick={handleEncryptAes}
                    className="flex-1 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs"
                  >
                    Encrypt AES-256-GCM
                  </button>
                  <button
                    onClick={handleDecryptAes}
                    className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-lg text-xs"
                  >
                    Verify & Decrypt Tag
                  </button>
                </div>

                {aesResult && (
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Execution Speed:</span>
                      <span className="text-[#00ff88]">{aesResult.executionTimeMs} ms</span>
                    </div>
                    <div className="break-all">
                      <span className="text-slate-500">IV (96-bit):</span> {aesResult.ivHex}
                    </div>
                    <div className="break-all">
                      <span className="text-slate-500">Auth Tag (128-bit):</span>{' '}
                      <span className="text-[#00ff88]">{aesResult.tagHex}</span>
                    </div>
                    <div className="break-all">
                      <span className="text-slate-500">Ciphertext:</span>{' '}
                      <span className="text-cyan-300">{aesResult.ciphertextHex}</span>
                    </div>
                  </div>
                )}

                {aesDecryptedOutput && (
                  <div className="p-2.5 rounded-lg border bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]">
                    <strong>Decrypted Plaintext:</strong> {aesDecryptedOutput}
                  </div>
                )}
              </div>

              {/* Right: Statistical Cryptanalysis / Caesar Solver */}
              <div className="bg-slate-900/70 p-5 rounded-2xl border border-slate-800 space-y-4 font-mono text-xs">
                <div className="flex items-center space-x-2 text-[#a855f7] font-bold">
                  <Search className="w-4 h-4" />
                  <span>INDEX OF COINCIDENCE (IoC) & CHI-SQUARED SOLVER</span>
                </div>

                <div className="space-y-2">
                  <label className="text-slate-400 text-[11px]">CIPHERTEXT SAMPLE</label>
                  <textarea
                    value={caesarCiphertext}
                    onChange={(e) => setCaesarCiphertext(e.target.value)}
                    rows={3}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-white"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-[11px]">
                    Index of Coincidence: <strong className="text-cyan-400">{iocScore}</strong>{' '}
                    {iocScore > 0.06 ? '(Monoalphabetic / English)' : '(Polyalphabetic / High Entropy)'}
                  </span>
                  <button
                    onClick={handleCrackCaesar}
                    className="px-4 py-2 bg-[#7000ff]/20 hover:bg-[#7000ff]/30 border border-[#7000ff]/50 text-[#c084fc] font-bold rounded-lg text-xs"
                  >
                    Solve via Chi-Squared
                  </button>
                </div>

                <div className="space-y-2 pt-1">
                  <span className="text-slate-400 text-[11px] font-bold block">
                    BEST STATISTICAL DECRYPTION CANDIDATES (Ranked by Minimum χ²):
                  </span>
                  {caesarResults.map((res, i) => (
                    <div key={i} className={`p-2.5 rounded-lg border ${i === 0 ? 'bg-[#00ff88]/10 border-[#00ff88]/30' : 'bg-slate-950 border-slate-800'}`}>
                      <div className="flex justify-between items-center text-[10px] text-slate-400 mb-0.5">
                        <span className="font-bold text-white">Shift Offset: -{res.shift}</span>
                        <span>χ² Score: {res.chiSquared} (Lower is better)</span>
                      </div>
                      <p className={`text-xs ${i === 0 ? 'text-[#00ff88] font-bold' : 'text-slate-300'}`}>
                        {res.plaintext}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* RSA-OAEP 2048-Bit Key Generation Sandbox */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-slate-800 font-mono text-xs space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div className="flex items-center space-x-2 text-white font-bold">
                  <Key className="w-4 h-4 text-cyan-400" />
                  <span>Browser Hardware RSA-OAEP 2048-Bit Asymmetric Keypair Generator</span>
                </div>
                <button
                  disabled={isGeneratingRsa}
                  onClick={handleGenerateRsa}
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-colors"
                >
                  {isGeneratingRsa ? 'Generating 2048-Bit Primes...' : 'Generate Real RSA Keypair'}
                </button>
              </div>

              {rsaKeys && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="space-y-1">
                    <span className="text-cyan-400 text-[11px] font-bold">PUBLIC KEY (SPKI X.509 PEM):</span>
                    <pre className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-[10px] text-slate-300 overflow-x-auto max-h-36">
                      {rsaKeys.publicKeyPem}
                    </pre>
                  </div>
                  <div className="space-y-1">
                    <span className="text-amber-400 text-[11px] font-bold">PRIVATE KEY (PKCS#8 PEM):</span>
                    <pre className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-[10px] text-slate-400 overflow-x-auto max-h-36">
                      {rsaKeys.privateKeyPem}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
