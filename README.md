# AegisShield 🛡️ | Cyber Threat Defense & Intelligence Hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg?logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-38bdf8.svg?logo=tailwind-css)](https://tailwindcss.com/)
[![Web Crypto API](https://img.shields.io/badge/Security-Web%20Crypto%20API-00ff88.svg)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

> **AegisShield** is an advanced, production-grade cybersecurity operations center and diagnostic hub. Built with React 19, TypeScript, and modern cryptographic standards, AegisShield empowers security engineers, sysadmins, and cybersecurity learners to audit endpoints, analyze threat indicators, calculate password entropy, test network privacy postures, and train against social engineering attacks.

---

## 🌟 Key Features

### 1. 🔍 Multi-Engine Threat Scanner
* **URL & Web Domain Diagnostics:** Evaluates domain age, typosquatting homographs, SSL certificate validity, and heuristic patterns against 16+ simulated antimalware engines (CrowdStrike, Kaspersky, Microsoft Defender ATP, Bitdefender, Cloudflare Radar).
* **Local File Payload Heuristic Audit:** Computes true cryptographic hashes (**SHA-256**, **SHA-1**, **MD5**) entirely inside the browser using the native **Web Crypto API** (`crypto.subtle.digest`). Evaluates file Shannon entropy to detect packed binaries or encrypted payloads.
* **Audit Report Export:** Download structured JSON diagnostic reports with full engine telemetry.

### 2. ⚡ Deep Systems & Reverse Engineering Lab
* **PE & ELF Executable Header Parser:** Dissects DOS header, COFF header, Optional 64-bit header, Section tables (`.text`, `.rdata`, `.data`), and calculates section-by-section Shannon entropy to uncover obfuscated, encrypted, or packed malware (UPX/Themida).
* **Interactive Canonical Hex Dump Dissector:** 16-byte memory inspector with real-time data type decoding (`uint8`, `uint16-LE`, binary bitstrings, ASCII representations).
* **YARA Rule Compiler & Engine:** In-browser AST compiler and scanner supporting meta tags, string types (ASCII/nocase, hex wildcards `??`, regexes), and boolean evaluation conditions (`any of them`, `all of them`, `$a and $b`).
* **x86_64 Stack Frame & Buffer Overflow Visualizer:** Step-by-step visualizer for call frames, Stack Canaries (`__stack_chk_guard`), Saved RBP, and Return Address (RIP) hijack verification with ASLR and DEP/NX mitigation toggles.
* **Hardware Cryptography & Cipher Solver:** Hardware-accelerated AES-256-GCM authenticated encryption (100k PBKDF2 iterations), browser-generated RSA-OAEP 2048-bit keypairs with PEM export, and Index of Coincidence (IoC) + Chi-Squared statistical frequency cipher breakers.

### 2. 🔐 Cryptographic Password & Breach Defense Lab
* **Information Entropy Analyzer:** Computes mathematical Shannon entropy in bits ($E = L \cdot \log_2(R)$) adjusted for character frequency and repetition.
* **GPU Cluster Crack-Time Estimation:** Benchmarks resistance against high-performance password cracking clusters (e.g. 8x NVIDIA RTX 4090 hashcat rigs at 10+ Billion guesses/second).
* **NIST 800-63B Compliance Checklist:** Validates password length (12+ characters), mixed case, numeric digits, and special symbols.
* **High-Entropy Generator:** Generates both cryptographically random character sequences and memorable Diceware/XKCD multi-word passphrases with 1-click clipboard copy.
* **Dark Web Breach Archive Search:** Simulates checking compromised credential dumps (Collection #1, Canva, LinkedIn, Adobe, Zynga) with explicit data-class exposures.

### 3. 🌐 Network Posture & WebRTC Leak Diagnostic
* **Client Gateway Detection:** Probes public IP adapter metadata with graceful privacy-preserving fallbacks.
* **WebRTC STUN Candidate Privacy Audit:** Uses real `RTCPeerConnection` probing to detect private or public IP leakage via mDNS masking.
* **Transport Layer Security (TLS 1.3):** Validates HTTP Strict Transport Security (HSTS) headers, cipher suites (AES-256-GCM), and root certificate validation.
* **Stateful Port Inspection Console:** Live streaming terminal output probing standard TCP ports (80, 443, 22, 3389, 445, 8080).

### 4. 🎣 Interactive Phishing & Social Engineering Lab
* **Realistic Attack Scenarios:** Simulates deceptive corporate notifications, fake IT password migration demands, wire transfer alerts, and MFA fatigue bypasses.
* **Live Hyperlink Inspection:** Hover-to-inspect link target reveals deceptive URL redirection versus display text.
* **Granular Red-Flag Analysis:** Post-mortem breakdowns highlighting typosquatted domains, header spoofing, and urgency pressure.
* **Phishing Readiness IQ:** Dynamic score tracking displayed across the SOC dashboard.

### 5. 🐛 CVE & Zero-Day Vulnerability Explorer
* **Searchable Threat Database:** Live lookup of critical CVEs with CVSS v3.1 vector severity ratings (e.g., Chromium V8, Linux eBPF, OpenSSL Kyber, Apache HTTP).
* **Immediate Remediation Steps:** Practical vendor patch guidance and mitigation workarounds.

### 6. 🛡️ Interactive Defense Vault & Hardening Checklists
* **Actionable Countermeasures:** Step-by-step playbooks for FIDO2 Hardware Keys (YubiKey), WireGuard VPN tunnels, the **3-2-1-1 Ransomware Backup Rule**, and OS zero-day attack surface reduction.
* **Interactive Checklist:** Save and track hardening tasks locally; export custom markdown checklists (`.md`).
* **Executive Security Report:** 1-click printable and JSON-exportable executive posture summary.

---

## 🚀 Quickstart

### Prerequisites
* **Node.js** >= 18.0.0
* **npm** >= 9.0.0 (or pnpm / yarn)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/aegisshield-cyber-defense.git

# 2. Navigate to project root
cd aegisshield-cyber-defense

# 3. Install dependencies
npm install

# 4. Start local development server
npm run dev
```

Visit `http://localhost:3000` (or `http://localhost:5173`) in your browser.

### Building for Production

```bash
npm run build
```

The production assets will be built into the `dist/` folder, ready for deployment to Cloud Run, Vercel, Netlify, or static web servers.

---

## 📁 Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI pipeline (build & typecheck)
├── src/
│   ├── components/            # Modular UI Components
│   │   ├── Header.tsx         # Navigation & status bar
│   │   ├── Dashboard.tsx      # SOC operations command center & realtime feed
│   │   ├── ThreatScanner.tsx  # Multi-engine URL & file scanner
│   │   ├── PasswordBreachLab.tsx # Entropy calculator & breach search
│   │   ├── NetworkAudit.tsx   # WebRTC leak test & port scanner
│   │   ├── PhishingLab.tsx    # Interactive social engineering lab
│   │   ├── DefenseVault.tsx   # Hardening checklists & export
│   │   ├── CveExplorer.tsx    # CVE zero-day database
│   │   ├── ReportModal.tsx    # Executive security report modal
│   │   └── GitHubProjectModal.tsx # In-app repo inspector
│   ├── data/
│   │   └── mockSecurityData.ts # Threat feeds, breach catalog, CVEs, questions
│   ├── types/
│   │   └── security.ts        # Strict TypeScript type definitions
│   ├── utils/
│   │   ├── cryptoUtils.ts     # Native Web Crypto hashing & Shannon entropy
│   │   └── networkUtils.ts    # WebRTC probing & port diagnostics
│   ├── App.tsx                # Main application state & view controller
│   ├── index.css              # Tailwind v4 theme, animations, scan-line styles
│   └── main.tsx               # React 19 root entrypoint
├── package.json
├── tsconfig.json
├── vite.config.ts
├── LICENSE                    # MIT License
└── README.md
```

---

## 🔒 Privacy & Cryptographic Safety

1. **Zero Data Transmission:** AegisShield executes all cryptographic hashing (SHA-256, SHA-1) and Shannon entropy computations locally in the client using the browser's native `window.crypto.subtle` API.
2. **Zero Storage of Credentials:** Evaluated passwords, usernames, and test email addresses are never sent to external servers or persisted in cookies/local storage.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
