/**
 * YARA Rule Compiler & Heuristic Pattern Matching Engine in TypeScript
 * Tokenizes, compiles, and evaluates YARA rules against binary/text buffers.
 */

export interface YaraMatch {
  ruleName: string;
  matched: boolean;
  meta: Record<string, string>;
  matchedStrings: {
    identifier: string;
    type: 'text' | 'hex' | 'regex';
    offset: number;
    offsetHex: string;
    matchedValue: string;
  }[];
  executionTimeMs: number;
}

export interface ParsedYaraRule {
  name: string;
  meta: Record<string, string>;
  strings: {
    id: string;
    type: 'text' | 'hex' | 'regex';
    value: string;
    nocase?: boolean;
    hexBytes?: (number | null)[];
    regexObj?: RegExp;
  }[];
  condition: string;
}

/**
 * Parses YARA rule source text
 */
export function compileYaraRule(source: string): ParsedYaraRule {
  const meta: Record<string, string> = {};
  const strings: ParsedYaraRule['strings'] = [];
  let name = 'AnonymousRule';
  let condition = 'any of them';

  // Extract rule name: rule <Name>
  const ruleMatch = source.match(/rule\s+([A-Za-z0-9_]+)/i);
  if (ruleMatch) {
    name = ruleMatch[1];
  }

  // Extract meta block
  const metaBlock = source.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|\})/i);
  if (metaBlock) {
    const lines = metaBlock[1].split('\n');
    for (const line of lines) {
      const kv = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*["']?([^"'\n]+)["']?/);
      if (kv) {
        meta[kv[1]] = kv[2].trim();
      }
    }
  }

  // Extract strings block
  const stringsBlock = source.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|\})/i);
  if (stringsBlock) {
    const lines = stringsBlock[1].split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      // Text string: $a = "text" [nocase]
      const textMatch = trimmed.match(/^\s*(\$[A-Za-z0-9_]*)\s*=\s*"([^"]+)"(\s+nocase)?/);
      if (textMatch) {
        strings.push({
          id: textMatch[1],
          type: 'text',
          value: textMatch[2],
          nocase: Boolean(textMatch[3])
        });
        continue;
      }

      // Hex string: $h = { 48 89 E5 ?? 90 }
      const hexMatch = trimmed.match(/^\s*(\$[A-Za-z0-9_]*)\s*=\s*\{\s*([0-9A-Fa-f\s\?]+)\s*\}/);
      if (hexMatch) {
        const byteTokens = hexMatch[2].trim().split(/\s+/);
        const hexBytes = byteTokens.map(tok => {
          if (tok === '??' || tok === '?') return null;
          const parsed = parseInt(tok, 16);
          return isNaN(parsed) ? null : parsed;
        });

        strings.push({
          id: hexMatch[1],
          type: 'hex',
          value: hexMatch[2],
          hexBytes
        });
        continue;
      }

      // Regex string: $r = /regex/
      const regMatch = trimmed.match(/^\s*(\$[A-Za-z0-9_]*)\s*=\s*\/([^\/]+)\/([a-z]*)/);
      if (regMatch) {
        strings.push({
          id: regMatch[1],
          type: 'regex',
          value: regMatch[2],
          regexObj: new RegExp(regMatch[2], regMatch[3] || 'i')
        });
      }
    }
  }

  // Extract condition
  const condMatch = source.match(/condition\s*:\s*([\s\S]*?)(?=\}|\s*$)/i);
  if (condMatch) {
    condition = condMatch[1].trim();
  }

  return { name, meta, strings, condition };
}

/**
 * Executes a compiled YARA rule against byte buffer
 */
export function scanWithYara(rule: ParsedYaraRule, data: Uint8Array): YaraMatch {
  const startTime = performance.now();
  const matchedStrings: YaraMatch['matchedStrings'] = [];
  const matchedIds = new Set<string>();

  const textDecoder = new TextDecoder('utf-8', { fatal: false });
  const rawText = textDecoder.decode(data);

  for (const s of rule.strings) {
    if (s.type === 'text') {
      const searchTarget = s.nocase ? rawText.toLowerCase() : rawText;
      const searchTerm = s.nocase ? s.value.toLowerCase() : s.value;
      let pos = 0;
      while ((pos = searchTarget.indexOf(searchTerm, pos)) !== -1) {
        matchedStrings.push({
          identifier: s.id,
          type: 'text',
          offset: pos,
          offsetHex: '0x' + pos.toString(16).toUpperCase().padStart(6, '0'),
          matchedValue: s.value
        });
        matchedIds.add(s.id);
        pos += searchTerm.length;
        if (matchedStrings.length > 50) break;
      }
    } else if (s.type === 'hex' && s.hexBytes) {
      const pattern = s.hexBytes;
      const patLen = pattern.length;
      for (let i = 0; i <= data.length - patLen; i++) {
        let match = true;
        for (let j = 0; j < patLen; j++) {
          if (pattern[j] !== null && data[i + j] !== pattern[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          const sliceHex = Array.from(data.slice(i, i + Math.min(patLen, 16)))
            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
            .join(' ');

          matchedStrings.push({
            identifier: s.id,
            type: 'hex',
            offset: i,
            offsetHex: '0x' + i.toString(16).toUpperCase().padStart(6, '0'),
            matchedValue: sliceHex
          });
          matchedIds.add(s.id);
          i += patLen - 1;
          if (matchedStrings.length > 50) break;
        }
      }
    } else if (s.type === 'regex' && s.regexObj) {
      const match = rawText.match(s.regexObj);
      if (match && match.index !== undefined) {
        matchedStrings.push({
          identifier: s.id,
          type: 'regex',
          offset: match.index,
          offsetHex: '0x' + match.index.toString(16).toUpperCase().padStart(6, '0'),
          matchedValue: match[0]
        });
        matchedIds.add(s.id);
      }
    }
  }

  // Condition evaluation
  let isMatched = false;
  const condLower = rule.condition.toLowerCase();

  if (condLower.includes('all of them')) {
    isMatched = rule.strings.length > 0 && rule.strings.every(s => matchedIds.has(s.id));
  } else if (condLower.includes('any of them')) {
    isMatched = matchedIds.size > 0;
  } else {
    // Custom boolean expression e.g. $a and $b
    try {
      let expr = rule.condition;
      for (const s of rule.strings) {
        const idRegex = new RegExp('\\' + s.id + '\\b', 'g');
        expr = expr.replace(idRegex, matchedIds.has(s.id) ? 'true' : 'false');
      }
      expr = expr.replace(/\band\b/gi, '&&').replace(/\bor\b/gi, '||').replace(/\bnot\b/gi, '!');
      // Safe boolean eval
      isMatched = Boolean(Function(`"use strict"; return (${expr});`)());
    } catch {
      isMatched = matchedIds.size > 0;
    }
  }

  const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

  return {
    ruleName: rule.name,
    matched: isMatched,
    meta: rule.meta,
    matchedStrings,
    executionTimeMs
  };
}

export const YARA_PRESET_RULES: { name: string; description: string; ruleText: string; testPayload: string }[] = [
  {
    name: 'LockBit_3_0_Ransomware_Signature',
    description: 'Detects LockBit Black / 3.0 file header marker, registry persistence strings, and C2 parameters.',
    ruleText: `rule LockBit_3_0_Indicator
{
    meta:
        author = "Aegis Threat Intel"
        severity = "CRITICAL"
        description = "Detects LockBit 3.0 Black Ransomware IOCs"
        date = "2026-10-25"
    strings:
        $s1 = "LockBit 3.0 is also known as Black" nocase
        $s2 = "-pass lockbit" nocase
        $hex = { 55 89 E5 83 EC ?? 53 56 57 }
        $c2 = /https?:\\\/\\\/[a-z0-9\\.\\-]+\\\/lb3_gate\\.php/
    condition:
        any of them
}`,
    testPayload: `=== SAMPLE MALICIOUS MEMORY DUMP ===
Target path: C:\\Windows\\System32\\srvhost.exe
Command executed: C:\\Temp\\payload.exe -pass lockbit -path D:\\Backups
Notice: LockBit 3.0 is also known as Black ransomware payload staged.
C2 Beaconing: http://185.220.101.5/lb3_gate.php?guid=984128`
  },
  {
    name: 'Cobalt_Strike_Malleable_C2_Beacon',
    description: 'Signatures for Cobalt Strike DNS/HTTP beacon metadata injection and reflective loader.',
    ruleText: `rule Cobalt_Strike_Beacon_Loader
{
    meta:
        author = "SOC Red Team Research"
        threat_type = "Command & Control"
        cvss = "9.0"
    strings:
        $ref_loader = "ReflectiveLoader"
        $pipe = "\\\\.\\pipe\\MSSE-"
        $magic = { 4D 5A 41 52 55 48 89 E5 }
    condition:
        any of them
}`,
    testPayload: `MZARUH\x89\xE5\x90\x90
[DEBUG] Initializing in-memory injection stub.
Exported symbol: ReflectiveLoader found at RVA 0x1400.
Named Pipe allocated: \\\\.\\pipe\\MSSE-8491-beacon-pipe ready for IPC.`
  },
  {
    name: 'Generic_PHP_WebShell_Backdoor',
    description: 'Detects obfuscated PHP code execution primitives: eval, assert, base64_decode, and passthru.',
    ruleText: `rule PHP_Webshell_Obfuscated_Eval
{
    meta:
        author = "Web Application Firewall SIG"
        category = "WebShell"
    strings:
        $p1 = "eval(" nocase
        $p2 = "base64_decode(" nocase
        $p3 = "passthru(" nocase
        $p4 = "shell_exec(" nocase
    condition:
        ($p1 and $p2) or ($p3 and $p4)
}`,
    testPayload: `<?php
// Silent remote administration endpoint
if(isset($_POST['cmd'])) {
    $code = base64_decode($_POST['cmd']);
    eval($code);
}
?>`
  }
];
