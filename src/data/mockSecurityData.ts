import { ThreatFeedItem, BreachEntry, PhishingQuestion, CVEItem, DefenseGuide } from '../types/security';

export const INITIAL_THREAT_FEED: ThreatFeedItem[] = [
  {
    id: 'THREAT-9941',
    type: 'Zero-Day Exploit',
    target: 'CVE-2026-9812 Chromium V8 JIT Parser',
    level: 'CRITICAL',
    status: 'Patched',
    timestamp: '2 mins ago',
    description: 'Out-of-bounds memory write in V8 JavaScript engine allowing remote code execution via malformed WebAssembly bytecode.',
    cve: 'CVE-2026-9812',
    ioc: 'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  },
  {
    id: 'THREAT-9940',
    type: 'Phishing Campaign',
    target: 'login-update-paypal-support.net',
    level: 'HIGH',
    status: 'Blocked',
    timestamp: '7 mins ago',
    description: 'Credential harvesting kit mimicking corporate SSO and payment portals with reverse proxy MFA bypass (Evilginx3).',
    ioc: 'Domain: login-update-paypal-support.net'
  },
  {
    id: 'THREAT-9939',
    type: 'Malware Variant',
    target: 'Trojan.Win32.AgentTesla.v9',
    level: 'CRITICAL',
    status: 'Quarantined',
    timestamp: '14 mins ago',
    description: '.NET based spyware targeting saved browser credentials, Telegram desktop sessions, and cryptocurrency cold storage seeds.',
    cve: 'CVE-2025-4112',
    ioc: 'MD5: 8b1a9953c4611296a827abf8c47804d7'
  },
  {
    id: 'THREAT-9938',
    type: 'Ransomware C2',
    target: 'c2-server-109.blackcat-alpha.onion.link',
    level: 'CRITICAL',
    status: 'Blacklisted',
    timestamp: '28 mins ago',
    description: 'Active command-and-control beaconing endpoint for BlackCat/ALPHV affiliate payload staging.',
    ioc: 'IP: 185.220.101.55 / Port 8443'
  },
  {
    id: 'THREAT-9937',
    type: 'Expired SSL / Man-in-the-Middle',
    target: 'api-internal-gateway.legacy-service.org',
    level: 'LOW',
    status: 'Warning',
    timestamp: '42 mins ago',
    description: 'TLS certificate expired 14 hours ago. Client sessions defaulting to insecure cipher downgrade risks.',
    ioc: 'Issuer: R3 Let\'s Encrypt (Expired)'
  },
  {
    id: 'THREAT-9936',
    type: 'Typosquatting Probe',
    target: 'g00gle-accounts-verify.com',
    level: 'HIGH',
    status: 'Blocked',
    timestamp: '1 hour ago',
    description: 'Homograph international domain attack targeting OAuth tokens of administrative users.',
    ioc: 'Domain: g00gle-accounts-verify.com'
  },
  {
    id: 'THREAT-9935',
    type: 'DDoS Botnet Staging',
    target: 'Mirai.variant.x86_arm64',
    level: 'MEDIUM',
    status: 'Investigating',
    timestamp: '1 hour ago',
    description: 'Telnet/SSH dictionary brute-forcing against consumer IoT routers on default credentials (admin/admin).',
    ioc: 'Port 23/2323 syn-flood signatures'
  }
];

export const SECURITY_SCAN_ENGINES = [
  'Kaspersky Threat Engine',
  'CrowdStrike Falcon',
  'Bitdefender GravityZone',
  'Microsoft Defender ATP',
  'Sophos Intercept X',
  'ESET LiveGrid',
  'Cloudflare Radar',
  'Palo Alto WildFire',
  'SentinelOne Singularity',
  'Fortinet FortiGuard',
  'Trend Micro Smart Protection',
  'Symantec DeepSight',
  'Cisco Talos Intelligence',
  'Avast Heuristic Scanner',
  'Malwarebytes Nebula',
  'Google Safe Browsing'
];

export const MOCK_BREACH_DATABASE: Record<string, BreachEntry[]> = {
  'pwned': [
    {
      name: 'Collection1',
      title: 'Collection #1 Mega Dump',
      domain: 'mega.nz',
      breachDate: '2019-01-07',
      addedDate: '2019-01-16',
      pwnCount: 772904991,
      dataClasses: ['Email addresses', 'Plaintext Passwords', 'De-hashed Hashes'],
      isVerified: true,
      description: 'A massive compilation of 2,692,818,238 rows consisting of cleaned combo lists originating from thousands of separate breaches.'
    },
    {
      name: 'Canva',
      title: 'Canva Design Platform',
      domain: 'canva.com',
      breachDate: '2019-05-24',
      addedDate: '2019-05-28',
      pwnCount: 137000000,
      dataClasses: ['Email addresses', 'Names', 'Cryptographic bcrypt hashes', 'Geographic locations'],
      isVerified: true,
      description: 'In May 2019, graphic design tool website Canva suffered a security incident attributed to the threat actor Gnosticplayers.'
    },
    {
      name: 'LinkedIn2021',
      title: 'LinkedIn Scraped Archive',
      domain: 'linkedin.com',
      breachDate: '2021-06-22',
      addedDate: '2021-06-29',
      pwnCount: 700000000,
      dataClasses: ['Full names', 'Email addresses', 'Phone numbers', 'Workplace histories', 'Salary estimates'],
      isVerified: true,
      description: 'Data scraped from 700 million LinkedIn users was offered for sale on a dark web forum after exploitation of public API endpoints.'
    }
  ],
  'admin': [
    {
      name: 'Adobe2013',
      title: 'Adobe Systems Corporate Breach',
      domain: 'adobe.com',
      breachDate: '2013-10-04',
      addedDate: '2013-12-04',
      pwnCount: 153000000,
      dataClasses: ['Email addresses', 'Password hints', 'Symmetric DES encrypted passwords', 'Usernames'],
      isVerified: true,
      description: 'In October 2013, 153 million Adobe accounts were breached with encrypted passwords and unencrypted password hints.'
    },
    {
      name: 'Dropbox',
      title: 'Dropbox Cloud Storage',
      domain: 'dropbox.com',
      breachDate: '2012-07-01',
      addedDate: '2016-08-31',
      pwnCount: 68680741,
      dataClasses: ['Email addresses', 'Salted bcrypt & SHA1 passwords'],
      isVerified: true,
      description: 'In mid-2012, Dropbox suffered a credential stuffing breach when an employee reused an unhashed password from a previous incident.'
    }
  ],
  'test': [
    {
      name: 'Zynga',
      title: 'Zynga Gaming Services',
      domain: 'zynga.com',
      breachDate: '2019-09-01',
      addedDate: '2019-12-19',
      pwnCount: 172855360,
      dataClasses: ['Email addresses', 'Usernames', 'Salted SHA-1 passwords', 'Phone numbers'],
      isVerified: true,
      description: 'In September 2019, the mobile games company Zynga disclosed a massive breach affecting users of Words With Friends and Draw Something.'
    }
  ]
};

export const PHISHING_QUESTIONS: PhishingQuestion[] = [
  {
    id: 'PHISH-01',
    title: 'Urgent Financial Suspension Notice',
    senderName: 'PayPal Security Team',
    senderEmail: 'support@paypaI-security-update.com',
    recipient: 'security-audit@yourorg.com',
    subject: 'URGENT: Your Account Has Been Locked Due to Suspicious Activity',
    date: 'Today at 09:14 AM',
    body: 'Dear Customer,\n\nWe detected an unauthorized login attempt from an unknown IP address in Moscow, Russia. To protect your financial balances, all withdrawal privileges have been suspended.\n\nPlease verify your identity immediately within the next 24 hours to prevent permanent account termination.',
    linkText: 'Verify Account & Restore Access Now',
    linkUrl: 'https://www.paypal.com/signin',
    actualDestination: 'http://auth.paypaI-security-update.com/login?token=9823h89',
    isPhishing: true,
    difficulty: 'EASY',
    redFlags: [
      'Typosquatting: Sender domain uses a capital "I" instead of lowercase "l" (paypaI instead of paypal).',
      'Artificial Sense of Urgency: "within 24 hours or account permanent termination".',
      'Deceptive Link: Visible text shows paypal.com, but destination URL directs to unencrypted http domain.'
    ],
    explanation: 'Definite Phishing scam! The email relies on high-stress panic ("Account Locked"), uses an international lookalike domain, and masks an unsafe HTTP destination underneath legitimate-looking anchor text.'
  },
  {
    id: 'PHISH-02',
    title: 'Official Dependency Vulnerability Notice',
    senderName: 'GitHub Dependabot',
    senderEmail: 'notifications@github.com',
    recipient: 'developer@yourorg.com',
    subject: '[GitHub] Security Advisory: High severity vulnerability in axios dependency',
    date: 'Yesterday at 04:30 PM',
    body: 'Hello,\n\nA new security advisory (CVE-2026-1049) was published affecting the package "axios" used in your repository "enterprise-frontend".\n\nNo immediate action via external forms is required. You can review the automated pull request directly in your GitHub repository dashboard to merge the fix.',
    linkText: 'View Repository Security Tab',
    linkUrl: 'https://github.com/my-org/enterprise-frontend/security',
    actualDestination: 'https://github.com/my-org/enterprise-frontend/security',
    isPhishing: false,
    difficulty: 'MEDIUM',
    legitIndicators: [
      'Official authenticated sender (@github.com with verified SPF, DKIM, and DMARC passes).',
      'No requests for credentials, passwords, or personal identity numbers.',
      'Hyperlink points exactly to the legitimate destination on github.com.'
    ],
    explanation: 'Legitimate notification! Legitimate service notices direct you into your existing dashboard workflow and do not demand urgent credentials or external software downloads.'
  },
  {
    id: 'PHISH-03',
    title: 'Corporate IT Mandatory Migration',
    senderName: 'Internal IT ServiceDesk',
    senderEmail: 'it-support@internal-corp-portal.xyz',
    recipient: 'employee@company.com',
    subject: 'MANDATORY ACTION: IT Infrastructure Migration & Password Resets',
    date: 'Today at 08:02 AM',
    body: 'Good morning Team,\n\nOur IT systems are transitioning to Cloud Active Directory tonight at 18:00 EST. All users must confirm their current network password and Active Directory username in the attached form before 17:00 EST to avoid access termination.',
    linkText: 'Open Employee Verification Form',
    linkUrl: 'http://corp-directory-sync.xyz/auth',
    actualDestination: 'http://corp-directory-sync.xyz/auth',
    isPhishing: true,
    difficulty: 'EASY',
    redFlags: [
      'Suspicious TLD (.xyz instead of official corporate domain).',
      'Asks for CURRENT passwords (legitimate IT departments NEVER ask you to reveal existing passwords).',
      'Strict artificial deadline threatening disruption to employee work.'
    ],
    explanation: 'Phishing! Cardinal rule of corporate IT: IT administrators will NEVER ask you to disclose or submit your existing passwords. Any email soliciting current passwords is an attack.'
  },
  {
    id: 'PHISH-04',
    title: 'Shared Executive Compensation Review',
    senderName: 'Google Drive Document Share',
    senderEmail: 'drive-shares-noreply@google-workspace-docs.top',
    recipient: 'finance-lead@company.com',
    subject: 'HR Director shared "Q4_Confidential_Bonus_Review_2026.pdf" with you',
    date: 'Today at 11:20 AM',
    body: 'Human Resources has invited you to view the confidential compensation structure adjustments for your department.\n\nClick below to authenticate with your Microsoft / Google Single Sign-On credentials to unlock the encrypted document.',
    linkText: 'Access Encrypted Document via SSO',
    linkUrl: 'https://drive.google.com/file/d/908234...',
    actualDestination: 'https://login-microsoft-sso-bypass.cfd/auth?target=bonus',
    isPhishing: true,
    difficulty: 'HARD',
    redFlags: [
      'Sender domain google-workspace-docs.top is NOT google.com.',
      'Lure exploits financial curiosity & sensitive insider data (bonus sheet).',
      'Prompts cross-provider SSO authentication to harvest corporate credentials.'
    ],
    explanation: 'Spear-Phishing Attack! Attackers frequently leverage payroll, salary schedules, and bonus rumors to entice employees into clicking without inspecting the sender email address.'
  },
  {
    id: 'PHISH-05',
    title: 'Bank Wire Transfer Receipt',
    senderName: 'Chase Commercial Banking',
    senderEmail: 'no-reply@commercial.chase.com',
    recipient: 'treasury@company.com',
    subject: 'Notification of Inbound Wire Transfer #W-9812401',
    date: '2 days ago',
    body: 'Your business account received an inbound federal wire of $142,500.00 USD on October 25, 2026.\n\nYou can log into your Chase Commercial Online Banking session as usual through your bookmarked banking portal to view cleared transactions.',
    linkText: 'Chase Commercial Online Login',
    linkUrl: 'https://www.chase.com/commercial-banking',
    actualDestination: 'https://www.chase.com/commercial-banking',
    isPhishing: false,
    difficulty: 'MEDIUM',
    legitIndicators: [
      'Sent from valid commercial.chase.com subdomain with strict DMARC enforcement.',
      'Does not pressure user to download attachments or click emergency verification links.',
      'Explicitly reminds user to log in via their regular bookmarked portal.'
    ],
    explanation: 'Legitimate banking notification! High-security financial institutions explicitly encourage customers to navigate via known bookmarks rather than embedding risky action buttons.'
  },
  {
    id: 'PHISH-06',
    title: 'Multi-Factor Authentication Exhaustion (MFA Fatigue)',
    senderName: 'Identity Access Management',
    senderEmail: 'security-alerts@okta-support-tickets.net',
    recipient: 'sec-ops@company.com',
    subject: 'Action Required: Repeated MFA Push Requests Detected',
    date: 'Today at 02:44 AM',
    body: 'We detected multiple MFA push prompts denied on your authenticator device. To disable notifications, please click "Cancel Authentication Session" and verify your 6-digit backup code.',
    linkText: 'Cancel Authentication Session & Re-enroll',
    linkUrl: 'https://okta-support-tickets.net/cancel-mfa',
    actualDestination: 'https://okta-support-tickets.net/cancel-mfa',
    isPhishing: true,
    difficulty: 'HARD',
    redFlags: [
      'Unsolicited middle-of-the-night notification attempting to trigger MFA fatigue or OTP interception.',
      'Untrusted third-party domain (okta-support-tickets.net instead of okta.com or company sso).',
      'Requests backup TOTP codes which grants immediate access without hardware key protection.'
    ],
    explanation: 'Phishing / MFA Bypass Attack! Modern threat actors weaponize fake security alerts to persuade victims to disclose secondary OTPs or approve rogue MFA prompts.'
  }
];

export const CVE_DATABASE: CVEItem[] = [
  {
    id: 'CVE-2026-9812',
    title: 'Chromium V8 Engine Out-of-Bounds Memory Corruption',
    cvss: 9.8,
    severity: 'CRITICAL',
    affectedProduct: 'Google Chrome < 142.0.7258.12, Edge < 142.0.7258.12, Brave, Opera',
    publishedDate: '2026-10-24',
    description: 'A heap buffer overflow flaw in the V8 bytecode compiler allows a remote attacker to execute arbitrary code within the renderer sandbox via a crafted HTML/WebAssembly file.',
    attackVector: 'Network / Unauthenticated Remote Exploitation',
    remediation: 'Upgrade Google Chrome and Chromium derivatives to version 142.0.7258.15 or later immediately.'
  },
  {
    id: 'CVE-2026-4419',
    title: 'Linux Kernel eBPF Subsystem Privilege Escalation',
    cvss: 8.4,
    severity: 'HIGH',
    affectedProduct: 'Linux Kernel 6.1 through 6.14',
    publishedDate: '2026-10-18',
    description: 'Improper bounds checking in the extended Berkeley Packet Filter (eBPF) verifier allows an unprivileged local user to achieve root escalation on container hosts.',
    attackVector: 'Local / Low Privilege',
    remediation: 'Apply upstream vendor patch kernel 6.14.3 or set `kernel.unprivileged_bpf_disabled = 1` via sysctl.'
  },
  {
    id: 'CVE-2026-3108',
    title: 'OpenSSL Timing Side-Channel in Kyber Post-Quantum KEM',
    cvss: 7.5,
    severity: 'HIGH',
    affectedProduct: 'OpenSSL 3.4.0',
    publishedDate: '2026-10-10',
    description: 'A non-constant-time comparison in the decapsulation procedure of ML-KEM / Kyber allows an attacker to recover secret keys via microarchitectural cache timing.',
    attackVector: 'Network / MitM Timing Analysis',
    remediation: 'Upgrade to OpenSSL 3.4.1 which implements constant-time array verification.'
  },
  {
    id: 'CVE-2026-1894',
    title: 'Apache HTTP Server Path Traversal in mod_proxy_rewrite',
    cvss: 6.8,
    severity: 'MEDIUM',
    affectedProduct: 'Apache HTTP Server 2.4.50 to 2.4.62',
    publishedDate: '2026-09-29',
    description: 'Misconfigured rewrite rules handling encoded forward slashes (%2F) can lead to request smuggling and access to internal upstream endpoints.',
    attackVector: 'Network / HTTP Request Header Manipulation',
    remediation: 'Disable UnsafeRewriteOptions or update to Apache HTTP Server 2.4.63.'
  },
  {
    id: 'CVE-2026-1102',
    title: 'Apple macOS & iOS CoreGraphics Memory Leak DoS',
    cvss: 5.3,
    severity: 'LOW',
    affectedProduct: 'macOS Sequoia 15.3, iOS 18.3',
    publishedDate: '2026-09-15',
    description: 'Processing a maliciously crafted SVG asset in Safari or Mail may result in rapid memory exhaustion and springboard restart.',
    attackVector: 'User Interaction / Web Browsing',
    remediation: 'Install macOS 15.3.1 and iOS 18.3.1 Security Update.'
  }
];

export const DEFENSE_GUIDES: DefenseGuide[] = [
  {
    id: 'GUIDE-MFA',
    category: 'Identity & Authentication',
    title: 'Multi-Factor Authentication (MFA / 2FA) Hardening',
    iconName: 'fingerprint',
    summary: 'Single passwords are fundamentally vulnerable to credential stuffing. Enforce resilient second-factor authentication across your core accounts.',
    priority: 'CRITICAL',
    actionableSteps: [
      'Migrate away from SMS/voice 2FA which is vulnerable to SIM-swapping and SS7 interception.',
      'Deploy hardware security keys (FIDO2 / WebAuthn like YubiKey 5 Series) for primary Google, GitHub, and email accounts.',
      'If using app-based TOTP (Google Authenticator, Aegis, 1Password), ensure encrypted cloud backups or offline vault backups exist.',
      'Store physical recovery emergency codes in a tamper-evident, fireproof offline location.',
      'Enable "Number Matching" in Microsoft Authenticator or Duo to block MFA fatigue push attacks.'
    ],
    toolsRecommended: ['YubiKey 5 NFC', 'Aegis Authenticator (Android)', 'Ente Auth (Cross-platform)', 'Bitwarden']
  },
  {
    id: 'GUIDE-WIFI',
    category: 'Network & Travel Security',
    title: 'Public Wi-Fi & WireGuard Encrypted Tunnels',
    iconName: 'wifi-off',
    summary: 'Untrusted public networks expose endpoints to ARP poisoning, rogue captive portals, and DNS interception.',
    priority: 'HIGH',
    actionableSteps: [
      'Disable "Auto-Join Known Networks" on iOS, Android, macOS, and Windows to prevent Wi-Fi Pineapple evil-twin attacks.',
      'Always route traffic through an encrypted WireGuard or OpenVPN tunnel before connecting to airport/hotel Wi-Fi.',
      'Configure Encrypted DNS over HTTPS (DoH) or DNS over TLS (DoT) with DNSSEC validation enabled (e.g. Quad9 or Cloudflare 1.1.1.2 for malware blocking).',
      'Verify the padlock and TLS certificate details on critical web portals before submitting authentication tokens.',
      'Turn off local network file-sharing (SMB, AirDrop to Everyone) in public spaces.'
    ],
    toolsRecommended: ['Mullvad VPN', 'ProtonVPN', 'Tailscale WireGuard', 'Cloudflare 1.1.1.1 + WARP', 'Quad9 (9.9.9.9)']
  },
  {
    id: 'GUIDE-BACKUP',
    category: 'Ransomware Immunity',
    title: 'Ransomware Protection: The 3-2-1-1 Backup Strategy',
    iconName: 'hard-drive',
    summary: 'Ransomware threat actors actively target online backups and network-attached storage (NAS). Immutable air-gapped copies guarantee recovery.',
    priority: 'CRITICAL',
    actionableSteps: [
      'Maintain at least 3 distinct copies of mission-critical data.',
      'Store backups on 2 different physical media types (e.g., fast NVMe SSD and cloud storage).',
      'Keep 1 copy in a geographically offsite location to protect against local fire/theft.',
      'Ensure 1 copy is completely air-gapped and immutable (e.g. cold unplugged hard drive or AWS S3 Object Lock in compliance mode).',
      'Conduct monthly disaster recovery drills to verify backup archive restoration speeds.'
    ],
    toolsRecommended: ['Veeam Backup & Replication', 'Restic / BorgBackup', 'AWS S3 Object Lock', 'Backblaze B2']
  },
  {
    id: 'GUIDE-PATCH',
    category: 'Endpoint Hardening',
    title: 'Zero-Day Attack Surface Reduction',
    iconName: 'shield-alert',
    summary: 'Over 85% of exploited vulnerabilities have had vendor patches available for weeks prior to compromise.',
    priority: 'HIGH',
    actionableSteps: [
      'Enable automated silent security updates for Operating Systems (Windows Update, macOS Software Update, unattended-upgrades).',
      'Audit and prune unnecessary browser extensions; compromised extensions are a premier vector for token exfiltration.',
      'Uninstall legacy runtimes (Adobe Flash, old Java JREs, Python 2.7) which retain unpatched CVEs.',
      'Enforce full-disk encryption (BitLocker with TPM PIN on Windows, FileVault 2 on macOS, LUKS on Linux).',
      'Activate browser sandboxing features like Chrome Enhanced Protection or Firefox Strict Tracking Protection.'
    ],
    toolsRecommended: ['Windows Defender Device Guard', 'macOS FileVault', 'uBlock Origin', 'Malwarebytes']
  }
];
