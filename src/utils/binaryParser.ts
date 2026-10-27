/**
 * Advanced Binary Structure Parser (PE, ELF, Mach-O) & Section Entropy Engine
 * Parses raw ArrayBuffer data into executable headers and computes per-section Shannon entropy.
 */

export interface PESection {
  name: string;
  virtualAddress: string;
  virtualSize: number;
  rawSize: number;
  rawPointer: number;
  entropy: number;
  characteristics: string[];
  isPacked: boolean;
}

export interface PEHeaderInfo {
  format: 'PE32' | 'PE32+ (x64)' | 'Unknown PE';
  machine: string;
  entryPoint: string;
  imageBase: string;
  subsystem: string;
  timestamp: string;
  securityFeatures: {
    aslr: boolean;
    dep: boolean;
    cfg: boolean;
    seh: boolean;
  };
  sections: PESection[];
  totalEntropy: number;
  packerDetected: string | null;
}

export interface ELFHeaderInfo {
  format: string;
  classType: string;
  endianness: string;
  osAbi: string;
  machine: string;
  entryPoint: string;
  type: string;
  totalEntropy: number;
}

export interface BinaryAnalysisResult {
  fileSize: number;
  magicHex: string;
  architecture: 'PE_WINDOWS' | 'ELF_LINUX' | 'MACHO_MACOS' | 'RAW_PAYLOAD';
  peInfo?: PEHeaderInfo;
  elfInfo?: ELFHeaderInfo;
  entropy: number;
  previewHex: string;
}

export function computeBufferEntropy(buffer: Uint8Array): number {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i++) {
    counts[buffer[i]]++;
  }
  let entropy = 0;
  const len = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

/**
 * Parses Windows Portable Executable (PE) headers
 */
export function parsePE(view: DataView, bytes: Uint8Array): PEHeaderInfo | null {
  try {
    // Check DOS magic 'MZ' (0x4D, 0x5A)
    if (bytes.length < 64 || bytes[0] !== 0x4D || bytes[1] !== 0x5A) {
      return null;
    }

    // Offset to PE Header (e_lfanew at 0x3C)
    const e_lfanew = view.getUint32(0x3C, true);
    if (e_lfanew + 24 >= bytes.length) return null;

    // Verify PE Signature 'PE\0\0' (0x50, 0x45, 0x00, 0x00)
    const peSig = view.getUint32(e_lfanew, false);
    if (peSig !== 0x50450000) return null;

    // COFF File Header
    const coffOffset = e_lfanew + 4;
    const machineId = view.getUint16(coffOffset, true);
    const numberOfSections = view.getUint16(coffOffset + 2, true);
    const timestampVal = view.getUint32(coffOffset + 4, true);
    const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);
    const characteristics = view.getUint16(coffOffset + 18, true);

    const timestamp = new Date(timestampVal * 1000).toISOString().replace('T', ' ').slice(0, 19);

    let machine = 'Unknown Architecture';
    if (machineId === 0x014C) machine = 'Intel x86 (32-bit)';
    else if (machineId === 0x8664) machine = 'AMD64 / x86_64 (64-bit)';
    else if (machineId === 0xAA64) machine = 'ARM64 Little-Endian';

    // Optional Header
    const optOffset = coffOffset + 20;
    const optMagic = view.getUint16(optOffset, true);
    const is64Bit = optMagic === 0x020B;
    const format = is64Bit ? 'PE32+ (x64)' : (optMagic === 0x010B ? 'PE32' : 'Unknown PE');

    const entryPointRVA = view.getUint32(optOffset + 16, true);
    const imageBase = is64Bit
      ? '0x' + view.getBigUint64(optOffset + 24, true).toString(16).toUpperCase()
      : '0x' + view.getUint32(optOffset + 28, true).toString(16).toUpperCase();

    // DllCharacteristics offset
    const dllCharOffset = is64Bit ? optOffset + 70 : optOffset + 70;
    const dllCharacteristics = view.getUint16(dllCharOffset, true);

    const aslr = (dllCharacteristics & 0x0040) !== 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    const dep = (dllCharacteristics & 0x0100) !== 0;  // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    const cfg = (dllCharacteristics & 0x4000) !== 0;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF
    const seh = (dllCharacteristics & 0x0400) === 0;  // IMAGE_DLLCHARACTERISTICS_NO_SEH not set

    // Section Headers
    const sectionHeaderStart = optOffset + sizeOfOptionalHeader;
    const sections: PESection[] = [];
    let highEntropyCount = 0;

    for (let i = 0; i < Math.min(numberOfSections, 16); i++) {
      const sOffset = sectionHeaderStart + i * 40;
      if (sOffset + 40 > bytes.length) break;

      let name = '';
      for (let j = 0; j < 8; j++) {
        const ch = bytes[sOffset + j];
        if (ch === 0) break;
        name += String.fromCharCode(ch);
      }

      const virtualSize = view.getUint32(sOffset + 8, true);
      const virtualAddress = '0x' + view.getUint32(sOffset + 12, true).toString(16).toUpperCase().padStart(8, '0');
      const rawSize = view.getUint32(sOffset + 16, true);
      const rawPointer = view.getUint32(sOffset + 20, true);
      const sectionFlags = view.getUint32(sOffset + 36, true);

      // Compute section entropy
      let secEntropy = 0;
      if (rawPointer + rawSize <= bytes.length && rawSize > 0) {
        const secSlice = bytes.subarray(rawPointer, rawPointer + rawSize);
        secEntropy = computeBufferEntropy(secSlice);
      }

      const isPacked = secEntropy > 7.1;
      if (isPacked) highEntropyCount++;

      const flagsDesc: string[] = [];
      if (sectionFlags & 0x20000000) flagsDesc.push('IMAGE_SCN_MEM_EXECUTE');
      if (sectionFlags & 0x40000000) flagsDesc.push('IMAGE_SCN_MEM_READ');
      if (sectionFlags & 0x80000000) flagsDesc.push('IMAGE_SCN_MEM_WRITE');
      if (sectionFlags & 0x00000020) flagsDesc.push('IMAGE_SCN_CNT_CODE');

      sections.push({
        name: name || `.section_${i}`,
        virtualAddress,
        virtualSize,
        rawSize,
        rawPointer,
        entropy: secEntropy,
        characteristics: flagsDesc,
        isPacked
      });
    }

    const totalEntropy = computeBufferEntropy(bytes);
    let packerDetected: string | null = null;

    if (sections.some(s => s.name.toUpperCase().includes('UPX'))) {
      packerDetected = 'UPX (Ultimate Packer for eXecutables)';
    } else if (sections.some(s => s.name.toUpperCase().includes('THEMIDA') || s.name.toUpperCase().includes('OREANS'))) {
      packerDetected = 'Themida / Oreans Virtual Machine Protector';
    } else if (highEntropyCount >= 2 && totalEntropy > 7.3) {
      packerDetected = 'Generic High-Entropy Crypter / Encrypted Payload Detected';
    }

    return {
      format,
      machine,
      entryPoint: '0x' + entryPointRVA.toString(16).toUpperCase().padStart(8, '0'),
      imageBase,
      subsystem: 'Windows CUI / GUI Subsystem',
      timestamp,
      securityFeatures: { aslr, dep, cfg, seh },
      sections,
      totalEntropy,
      packerDetected
    };
  } catch {
    return null;
  }
}

/**
 * Parses Linux ELF (Executable and Linkable Format) headers
 */
export function parseELF(view: DataView, bytes: Uint8Array): ELFHeaderInfo | null {
  try {
    if (bytes.length < 52 || bytes[0] !== 0x7F || bytes[1] !== 0x45 || bytes[2] !== 0x4C || bytes[3] !== 0x46) {
      return null;
    }

    const is64 = bytes[4] === 2;
    const isLittleEndian = bytes[5] === 1;
    const osAbiVal = bytes[7];

    const osAbis: Record<number, string> = {
      0: 'UNIX - System V',
      1: 'HP-UX',
      2: 'NetBSD',
      3: 'Linux',
      6: 'Solaris',
      9: 'FreeBSD',
      12: 'OpenBSD'
    };

    const typeVal = view.getUint16(16, isLittleEndian);
    const machineVal = view.getUint16(18, isLittleEndian);

    const typeMap: Record<number, string> = {
      1: 'ET_REL (Relocatable file)',
      2: 'ET_EXEC (Executable file)',
      3: 'ET_DYN (Shared object / PIE Position-Independent Executable)',
      4: 'ET_CORE (Core dump file)'
    };

    const machineMap: Record<number, string> = {
      3: 'x86 (Intel 80386)',
      62: 'Advanced Micro Devices X86-64',
      40: 'ARM 32-bit Architecture',
      183: 'AArch64 (ARM 64-bit Architecture)',
      243: 'RISC-V'
    };

    let entryPoint = '0x0';
    if (is64 && bytes.length >= 32) {
      entryPoint = '0x' + view.getBigUint64(24, isLittleEndian).toString(16).toUpperCase();
    } else if (!is64 && bytes.length >= 28) {
      entryPoint = '0x' + view.getUint32(24, isLittleEndian).toString(16).toUpperCase();
    }

    return {
      format: is64 ? 'ELF64' : 'ELF32',
      classType: is64 ? '64-bit Objects' : '32-bit Objects',
      endianness: isLittleEndian ? 'Little Endian (LSB)' : 'Big Endian (MSB)',
      osAbi: osAbis[osAbiVal] || `Unknown OS ABI (0x${osAbiVal.toString(16)})`,
      machine: machineMap[machineVal] || `Machine Code 0x${machineVal.toString(16)}`,
      entryPoint,
      type: typeMap[typeVal] || 'Unknown ELF Type',
      totalEntropy: computeBufferEntropy(bytes)
    };
  } catch {
    return null;
  }
}

/**
 * Universal binary inspector entrypoint
 */
export function analyzeBinary(input: ArrayBuffer | ArrayBufferLike | Uint8Array): BinaryAnalysisResult {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input as ArrayBuffer);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // Generate magic hex
  const magicHex = Array.from(bytes.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');

  let architecture: BinaryAnalysisResult['architecture'] = 'RAW_PAYLOAD';
  let peInfo: PEHeaderInfo | undefined = undefined;
  let elfInfo: ELFHeaderInfo | undefined = undefined;

  if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
    const parsed = parsePE(view, bytes);
    if (parsed) {
      architecture = 'PE_WINDOWS';
      peInfo = parsed;
    }
  } else if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
    const parsed = parseELF(view, bytes);
    if (parsed) {
      architecture = 'ELF_LINUX';
      elfInfo = parsed;
    }
  } else if (
    (bytes[0] === 0xFE && bytes[1] === 0xED && bytes[2] === 0xFA && (bytes[3] === 0xCE || bytes[3] === 0xCF)) ||
    (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
  ) {
    architecture = 'MACHO_MACOS';
  }

  // Preview hex string of first 128 bytes
  const previewHex = Array.from(bytes.slice(0, 64))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');

  return {
    fileSize: bytes.byteLength,
    magicHex,
    architecture,
    peInfo,
    elfInfo,
    entropy: computeBufferEntropy(bytes),
    previewHex
  };
}

/**
 * Creates a synthetic Windows PE binary for interactive demonstration
 */
export function createSyntheticPE(): Uint8Array {
  const buffer = new Uint8Array(1024);
  const view = new DataView(buffer.buffer);

  // 'MZ' header
  buffer[0] = 0x4D;
  buffer[1] = 0x5A;

  // e_lfanew pointer at 0x3C -> 0x80 (128)
  view.setUint32(0x3C, 0x80, true);

  const peOffset = 0x80;
  // 'PE\0\0'
  view.setUint32(peOffset, 0x50450000, false);

  // COFF Header (20 bytes)
  view.setUint16(peOffset + 4, 0x8664, true); // AMD64
  view.setUint16(peOffset + 6, 3, true);      // 3 Sections (.text, .rdata, .data)
  view.setUint32(peOffset + 8, Math.floor(Date.now() / 1000) - 86400, true); // TimeDateStamp
  view.setUint16(peOffset + 20, 0xF0, true);  // SizeOfOptionalHeader = 240
  view.setUint16(peOffset + 22, 0x0022, true); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // Optional Header 64-bit (starts at peOffset + 24)
  const optOffset = peOffset + 24;
  view.setUint16(optOffset, 0x020B, true); // PE32+
  view.setUint32(optOffset + 16, 0x1400, true); // AddressOfEntryPoint
  view.setBigUint64(optOffset + 24, 0x140000000n, true); // ImageBase
  view.setUint16(optOffset + 70, 0x4140, true); // DllCharacteristics: ASLR | DEP | CFG

  // Section Headers at optOffset + 240
  const secStart = optOffset + 240;

  // Section 1: .text
  const textName = new TextEncoder().encode('.text\0\0\0');
  buffer.set(textName, secStart);
  view.setUint32(secStart + 8, 0x1200, true);   // VirtualSize
  view.setUint32(secStart + 12, 0x1000, true);  // VirtualAddress
  view.setUint32(secStart + 16, 0x0200, true);  // RawSize = 512
  view.setUint32(secStart + 20, 0x0200, true);  // RawPointer = 512
  view.setUint32(secStart + 36, 0x60000020, true); // EXECUTE | READ | CODE

  // Fill .text raw data with simulated x86_64 code instructions
  for (let i = 512; i < 768; i++) {
    buffer[i] = (i * 37 + 13) % 256;
  }

  // Section 2: .rdata
  const rdataName = new TextEncoder().encode('.rdata\0\0');
  buffer.set(rdataName, secStart + 40);
  view.setUint32(secStart + 48, 0x0800, true);
  view.setUint32(secStart + 52, 0x3000, true);
  view.setUint32(secStart + 56, 0x0100, true);
  view.setUint32(secStart + 60, 0x0300, true);
  view.setUint32(secStart + 76, 0x40000040, true); // READ | INITIALIZED_DATA

  return buffer;
}
