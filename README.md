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

**Sentinel** bridges this gap by combining deep protocol analysis, linguistic NLP heuristics, geospatial origin mapping, and visual attribution graph generation into a unified, zero-dependency web platform.

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


## 🎯 Demo

| Preset Name | Threat Type | Key Forensic Indicators |
| :--- | :--- | :--- |
| **🚨 SBI NetBanking KYC Phish** | Phishing / Credential Harvester | DMARC Fail, Russian bulletproof host (`194.26.29.134`), urgent 24-hr account freeze threat, `.ru` phishing link. |
| **💼 CEO $385K Wire Fraud BEC** | Business Email Compromise | Executive display-name spoof ("Sundar Pichai"), Return-Path mismatch, Singapore VPN origin, NDA financial coercion. |
| **🔑 M365 Password Expiry Trap** | Typosquatting / Lookalike | Typosquatted domain (`m1crosoft-security-verify.com`), SPF SoftFail, Nigerian origin IP, password lure. |
| **✅ Google Cloud Invoice** | Legitimate Verified Mail | All SPF, DKIM, and DMARC checks PASS, genuine Google Mountain View IP, 0% threat score. |

---
