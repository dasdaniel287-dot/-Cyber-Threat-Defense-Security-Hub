export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ThreatStatus = 'Blocked' | 'Quarantined' | 'Blacklisted' | 'Warning' | 'Patched' | 'Investigating';

export interface ThreatFeedItem {
  id: string;
  type: string;
  target: string;
  level: ThreatSeverity;
  status: ThreatStatus;
  timestamp: string;
  description: string;
  cve?: string;
  ioc?: string;
}

export interface ScanEngineResult {
  engine: string;
  category: 'antivirus' | 'threat_intel' | 'sandbox' | 'heuristics';
  detected: boolean;
  result: string;
  updateTime: string;
}

export interface ScanReport {
  id: string;
  target: string;
  type: 'url' | 'file';
  timestamp: string;
  status: 'malicious' | 'suspicious' | 'clean';
  threatScore: number;
  engineHits: number;
  totalEngines: number;
  hashes?: {
    sha256: string;
    md5?: string;
    sha1?: string;
  };
  details: {
    domainAge?: string;
    registrar?: string;
    sslIssuer?: string;
    sslValid?: boolean;
    reputation?: string;
    fileType?: string;
    fileSizeBytes?: number;
    entropy?: number;
    heuristicsNotes: string[];
  };
  engineResults: ScanEngineResult[];
}

export interface PasswordAnalysis {
  password: string;
  length: number;
  entropy: number;
  score: number;
  crackTimeText: string;
  crackTimeSeconds: number;
  rules: {
    minLength: boolean;
    hasNumber: boolean;
    hasSymbol: boolean;
    hasMixedCase: boolean;
    noCommonWord: boolean;
  };
  classification: 'VERY_WEAK' | 'WEAK' | 'MODERATE' | 'STRONG' | 'CRYPTO_STRONG';
  suggestions: string[];
}

export interface BreachEntry {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  dataClasses: string[];
  isVerified: boolean;
  description: string;
}

export interface BreachRecord {
  email: string;
  isBreached: boolean;
  breaches: BreachEntry[];
  checkedAt: string;
}

export interface PortAuditItem {
  port: number;
  service: string;
  status: 'OPEN' | 'FILTERED' | 'REDIRECTED' | 'CLOSED';
  securityNote: string;
}

export interface NetworkDiagnosticState {
  ip: string;
  isSimulatedIp: boolean;
  location: string;
  isp: string;
  protocol: string;
  dnsServer: string;
  dnssecStatus: 'VALIDATED' | 'UNPROTECTED';
  webrtcLeak: 'PASSED' | 'FAILED' | 'TESTING';
  localIpsFound: string[];
  hstsStatus: 'ACTIVE' | 'NOT_ENFORCED';
  tlsVersion: string;
  cipherSuite: string;
  certAuthority: string;
  ports: PortAuditItem[];
  logs: string[];
}

export interface PhishingQuestion {
  id: string;
  title: string;
  senderName: string;
  senderEmail: string;
  recipient: string;
  subject: string;
  date: string;
  body: string;
  linkText?: string;
  linkUrl?: string;
  actualDestination?: string;
  hasAttachment?: boolean;
  attachmentName?: string;
  isPhishing: boolean;
  difficulty: 'EASY' | 'MEDIUM' | 'HARD';
  redFlags?: string[];
  legitIndicators?: string[];
  explanation: string;
}

export interface CVEItem {
  id: string;
  title: string;
  cvss: number;
  severity: ThreatSeverity;
  affectedProduct: string;
  publishedDate: string;
  description: string;
  attackVector: string;
  remediation: string;
  sourceUrl?: string;
}

export interface DefenseGuide {
  id: string;
  category: string;
  title: string;
  iconName: string;
  summary: string;
  priority: 'CRITICAL' | 'HIGH' | 'RECOMMENDED';
  actionableSteps: string[];
  toolsRecommended: string[];
}
