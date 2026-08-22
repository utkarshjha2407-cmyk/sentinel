# 🛡️ Sentinel — Smart India Hackathon (SIH) Prototype
### AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

> **Category:** Cybersecurity / Artificial Intelligence / Digital Forensics  
> **Target Audience:** Enterprise SOC Teams, Law Enforcement Agencies (LEAs), Financial Fraud Units, Institutional Administrators  
> **Tech Stack:** HTML5, CSS3 (Cyber SOC Dark Theme), Vanilla JavaScript (Modular ES6+), Leaflet.js, Web Crypto API  

---

## 🌟 Executive Summary & Problem Context
Email remains the #1 initial infection vector for cyberattacks globally (accounting for over 90% of data breaches). Traditional spam filters and perimeter email security tools (SEG) only offer binary "block/allow" filtering based on static blacklists and signatures. When a targeted attack strikes—such as **Business Email Compromise (BEC)**, **Lookalike Domain Spoofing**, or **Credential Phishing**—organizations lack the forensic capability to:
1. Trace the source relay path and find the true origin IP.
2. Accurately correlate email headers (`SPF`, `DKIM`, `DMARC`, `Return-Path`, `Message-ID`).
3. Geographically locate the sender infrastructure and detect bulletproof hosting / VPN / TOR anonymity networks.
4. Formulate court-admissible digital evidence with cryptographic chain of custody.

**SentinelMail AI** bridges this gap by combining deep protocol analysis, linguistic NLP heuristics, geospatial origin mapping, and visual attribution graph generation into a unified, zero-dependency web platform.

---

## 🚀 Key Features & Capabilities

### 1. 🔍 Deep Email Header & Protocol Forensics
- **Authentication Alignment:** Evaluates `SPF` (Pass/SoftFail/Fail), `DKIM` (cryptographic signature verification), and `DMARC` enforcement policies (`reject`/`quarantine`/`none`).
- **Header Anomaly Detection:** Detects `From` vs `Return-Path` domain divergence, `Reply-To` redirection, and mismatched `Message-ID` hostnames.
- **Relay Chain Reconstruction:** Parses all `Received:` hops in reverse chronological order to extract the earliest reliable public transmission node.

### 2. 🤖 AI & NLP Linguistic Threat Engine
- **Urgency & Psychological Coercion:** Detects artificial deadlines ("within 24 hours", "account suspended immediately").
- **BEC & Financial Diversion:** Flags executive impersonation patterns (wire transfer requests, escrow payments, secret acquisitions).
- **Credential Theft Cues:** Identifies password reset traps, KYC verification lures, and fake security alerts.
- **Malicious URL & Typosquatting Scanner:** Detects lookalike domains (e.g. `m1crosoft-security.com`, `sbi-online-security.in`), suspicious TLDs (`.ru`, `.xyz`), and raw IP URLs.

### 3. 🗺️ Global Relay Trace & Geolocation Map
- **Leaflet.js Interactive Cyber Globe:** Visualizes the journey of the email from the attacker's server, through intermediate relays, to the victim organization.
- **Infrastructure Intelligence:** Displays City, Country, ISP, Autonomous System Number (ASN), and flags TOR exit nodes, commercial VPNs, and bulletproof servers.

### 4. 🕸️ Forensic Attribution Vector Graph
- **Node-Link Threat Diagram:** Renders an interactive relationship graph connecting *Origin Infrastructure $\to$ Relay Servers $\to$ Spoofed Identity $\to$ Target Inbox*.
- **Attribution Verdict:** Categorizes the attack vector into *Spoofed External Domain*, *Compromised Account*, *BEC Wire Fraud*, or *Botnet Campaign*.

### 5. 🔒 Digital Evidence & ISO/IEC 27037 Compliance
- **Cryptographic Evidence Hashing:** Ingestion-time `SHA-256` and `MD5` hashes generated using the Web Crypto API to ensure tamper-proof integrity for legal proceedings.
- **Official Forensic Dossier Generator:** Instant printable / PDF export of comprehensive forensic reports formatted for law enforcement and CERT teams.
- **Incident Case Log:** Persistent local case file archive for tracking ongoing campaigns.


## ⚡ How to Run Locally

### Option 1: Double-Click (Zero Setup)
Simply open `index.html` in any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Brave).

### Option 2: Local HTTP Server (Recommended for Live Demos)
Run any of the following commands in the project folder:

```bash
# Using Python 3:
python3 -m http.server 8000

# Or using npx serve:
npx serve .
```
Then open `http://localhost:8000` in your browser.

---

## 🎯 1-Click Live Demo Guide for College Round Evaluators

During your hackathon presentation, click the **1-Click Presets** on top of the dashboard to instantly demonstrate different attack scenarios without needing to manually copy/paste headers:

| Preset Name | Threat Type | Key Forensic Indicators |
| :--- | :--- | :--- |
| **🚨 SBI NetBanking KYC Phish** | Phishing / Credential Harvester | DMARC Fail, Russian bulletproof host (`194.26.29.134`), urgent 24-hr account freeze threat, `.ru` phishing link. |
| **💼 CEO $385K Wire Fraud BEC** | Business Email Compromise | Executive display-name spoof ("Sundar Pichai"), Return-Path mismatch, Singapore VPN origin, NDA financial coercion. |
| **🔑 M365 Password Expiry Trap** | Typosquatting / Lookalike | Typosquatted domain (`m1crosoft-security-verify.com`), SPF SoftFail, Nigerian origin IP, password lure. |
| **✅ Google Cloud Invoice** | Legitimate Verified Mail | All SPF, DKIM, and DMARC checks PASS, genuine Google Mountain View IP, 0% threat score. |

---

## 📊 SIH PPT Presentation Structure (College Round Guide)

When creating your PowerPoint presentation, use this winning 8-slide structure:

### Slide 1: Title & Team
- **Title:** SentinelMail AI — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
- **Team Name & Member Roles:** (Frontend, Threat Modeling, Forensics, Presentation Lead)

### Slide 2: Problem Statement & Real-World Impact
- Billions of dollars lost annually to Business Email Compromise (BEC) and phishing.
- Existing spam filters are passive blockers—they don't answer: *Who sent it? Where did it come from? How was it routed?*

### Slide 3: Proposed Solution & Innovation
- An integrated Cyber-Forensic platform combining AI/NLP threat heuristics with RFC 5322 header inspection, relay hop traceability, and interactive geospatial mapping.

### Slide 4: System Architecture & Data Flow
- **Raw Ingestion** $\to$ **MIME Header Parsing** $\to$ **SPF/DKIM/DMARC Validation** $\to$ **NLP Semantic Scoring** $\to$ **GeoIP & ASN Lookup** $\to$ **Attribution Graph & Evidence Export**.

### Slide 5: Key Technical Modules
- **Module A:** Header & Authentication Forensics (DKIM cryptographic signature verification & DMARC alignment).
- **Module B:** NLP Coercion & Wire Fraud Detection.
- **Module C:** Global GeoTrace & Relay Map.
- **Module D:** ISO/IEC 27037 Evidentiary Chain of Custody (SHA-256).

### Slide 6: Live Prototype Demonstration
- Switch to the live browser window and run the 1-Click Demo presets. Show the risk gauge, the Leaflet map hop animation, the attribution graph, and the one-click printable Law Enforcement Forensic Dossier.

### Slide 7: Scalability & Future Scope
- Integration with institutional SIEM/SOAR platforms (Splunk, Elastic, Microsoft Sentinel).
- Deep learning Transformer-based NLP models (BERT / RoBERTa) for multilingual Indian language phishing detection.
- Automated AbuseIPDB & VirusTotal live API correlation.

### Slide 8: Conclusion & Q&A
- Summary of benefits for national cybersecurity, banking protection, and law enforcement support.

---

## 💡 Top Judge Q&A & Answers

**Q1: How does your system detect spoofing when the sender display name says "CEO"?**  
*Answer:* We cross-examine the display name in the `From:` header against the actual envelope sender (`Return-Path:`) and check the `DMARC` alignment. If the display name claims an internal executive identity but the message originates from an unauthorized external domain or generic webmail without SPF alignment, it is flagged as a BEC attack.

**Q2: Can attackers fake the `Received:` headers?**  
*Answer:* Attackers can only forge `Received:` headers before the email enters legitimate mail infrastructure. The first `Received:` header recorded by the receiving organization's MX server is immutable and contains the true sending IP of the connecting relay server. Our forensic engine traces the chain backwards to find the earliest authenticated public transmission node.

**Q3: How is this useful for Law Enforcement / Police Cyber Cells?**  
*Answer:* Law enforcement requires court-admissible evidence. Our platform generates SHA-256 cryptographic hashes of the raw email payload at ingestion to ensure non-repudiation and produces structured forensic dossiers containing IP addresses, ASNs, ISP details, and timestamped routing paths.
