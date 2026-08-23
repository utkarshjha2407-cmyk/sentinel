/**
 * SentinelMail AI - Forensic Analysis Engine
 * Core algorithms for Header Parsing, SPF/DKIM/DMARC Validation, NLP Threat Scoring,
 * GeoIP Hop Reconstruction, Domain Intelligence, and Evidence Integrity Hashing.
 */

class ForensicEngine {
    constructor() {
        this.typosquatDatabase = [
            { legitimate: "microsoft.com", lookalikes: ["m1crosoft", "micros0ft", "micro-soft", "m1crosoft-security", "office365-verify"] },
            { legitimate: "sbi.co.in", lookalikes: ["sbi-online", "sbi-security", "onlinesbi-update", "statebank-verify", "sbi-kyc"] },
            { legitimate: "google.com", lookalikes: ["g00gle", "google-security", "google-workspace-verify", "gmail-support"] },
            { legitimate: "hdfcbank.com", lookalikes: ["hdfc-banking", "hdfc-netbanking", "hdfc-kyc-alert"] },
            { legitimate: "amazon.com", lookalikes: ["amaz0n", "amazon-security-alert", "amz-order-confirm"] },
            { legitimate: "apple.com", lookalikes: ["app1e", "apple-id-verify", "icloud-security-center"] },
            { legitimate: "paypal.com", lookalikes: ["paypa1", "paypal-resolution-center", "paypal-service"] }
        ];

        this.urgencyKeywords = [
            "urgent", "immediately", "immediate action", "within 24 hours", "account suspended",
            "permanently suspended", "action required", "warning", "penalty", "freeze", "locked",
            "expire today", "in 2 hours", "confidential & urgent", "nda-restricted", "do not discuss"
        ];

        this.financialKeywords = [
            "wire transfer", "escrow", "invoice", "payment", "$", "rs.", "acquisition",
            "beneficiary", "foreign exchange", "cutoff", "bank account", "balance", "funds"
        ];

        this.credentialKeywords = [
            "password", "login credentials", "aadhaar", "netbanking", "verify your login",
            "keep my current password", "re-authenticate", "update kyc", "unlock account",
            "security center", "auth.php", "login.php"
        ];

        // Enhanced pattern detection for AI-like capabilities
        this.urgencyPatterns = [
            /\b(?:urgent|immediately|immediate action|within\s+\d+\s*(?:hours|hrs?))\b/i,
            /\b(?:account\s+(?:suspended|locked|frozen|terminated|closed))\b/i,
            /\b(?:verify|confirm|update|validate)\s+(?:your\s+)?(?:account|password|ssn|aadhaar|pan)\b/i,
            /\b(?:expires?\s+(?:in|within|today|tonight))\b/i,
            /\b(?:deadline|due\s+date|cutoff\s+(?:time|date))\b/i,
            /\b(?:penalty|fine|charge|fee)\s+(?:of\s+)?[\d,]+\s*(?:rs\.?|rs|inr|\$|usd|eur|gbp)\b/i,
            /\b(?:act\s+now|immediate\s+response|time\s+sensitive|limited\s+time)\b/i,
            /\b(?:security\s+alert|unauthorized\s+access|suspicious\s+activity)\b/i
        ];

        this.financialPatterns = [
            /\b(?:wire\s+transfer|bank\s+transfer|swift\s+payment|ach\s+transfer)\b/i,
            /\b(?:escrow\s+(?:account|payment|funds?|agent))\b/i,
            /\b(?:invoice\s+(?:#|number|id|due|payment|billing))\b/i,
            /\b(?:acquisition|takeover|merger|buyout|purchase\s+(?:agreement|terms))\b/i,
            /\b(?:offshore\s+(?:account|entity|company|jurisdiction))\b/i,
            /\b(?:confidential\s+(?:wire|transfer|payment|transaction|deal))\b/i,
            /\b(?:beneficiary\s+(?:details|information|account|name))\b/i,
            /\b(?:routing\s+(?:number|code|details|information))\b/i,
            /\b(?:swift\s+(?:bic|code|details))\b/i
        ];

        this.credentialPatterns = [
            /\b(?:password\s+(?:reset|change|update|expire|expiry))\b/i,
            /\b(?:login\s+(?:credentials|details|information|verification))\b/i,
            /\b(?:verify\s+(?:your\s+)?(?:identity|account|credentials|login))\b/i,
            /\b(?:keep\s+(?:my\s+)?current\s+password)\b/i,
            /\b(?:re[-\s]?authenticate|reauthenticate|sign\s+in\s+again)\b/i,
            /\b(?:update\s+(?:kyc|profile|details|information))\b/i,
            /\b(?:unlock\s+(?:account|access|lock))\b/i,
            /\b(?:security\s+(?:center|team|department|alert))\b/i,
            /\b(?:mfa|two[-\s]?factor|multifactor\s+authentication)\b/i,
            /\b(?:oauth|saml|ldap|active\s+directory)\b/i
        ];

        this.brandImpersonationPatterns = [
            // Financial/Banking
            /\b(?:state\s+bank|sbi|icici|hdfc|axis|kotak|pnb|canara|union\s+bank)\b/i,
            // Tech
            /\b(?:microsoft|office\s+365|m365|azure|windows|google|gmail|gmail|apple|icloud|paypal)\b/i,
            // E-commerce/Services
            /\b(?:amazon|flipkart|ebay|netflix|spotify|uber|ola|swiggy|zomato)\b/i,
            // Telecom/Utilities
            /\b(?:jio|airtel|vodafone|idea|bsnl|mtnl|tata\s+docomo|reliance)\b/i
        ];

        // Common stop words for TF-IDF
        this.stopWords = new Set([
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'has', 'he', 'in', 'is', 'it', 'its',
            'of', 'on', 'that', 'the', 'to', 'was', 'were', 'will', 'with', 'i', 'you', 'we', 'they', 'this',
            'that', 'these', 'those', 'am', 'pm', 'am', 'pm', 'please', 'kindly', 'dear', 'hello', 'hi'
        ]);

        // Threat Intelligence Manager
        this.threatIntelManager = new ThreatIntelManager();
    }

    /**
     * Parse raw email text into RFC 5322 structured headers and body
     */
    parseEmail(rawText) {
        if (!rawText || typeof rawText !== "string") {
            throw new Error("Invalid raw email payload provided.");
        }

        const normalized = rawText.replace(/\r\n/g, "\n");
        // Split header section from body by first occurrence of empty line
        const headerEndIndex = normalized.search(/\n\n/);

        let headerText = "";
        let bodyText = "";

        if (headerEndIndex !== -1) {
            headerText = normalized.substring(0, headerEndIndex);
            bodyText = normalized.substring(headerEndIndex + 2);
        } else {
            headerText = normalized;
            bodyText = "";
        }

        // Unfold multi-line headers (RFC 5322 folding: line starting with space or tab)
        const unfoldedLines = [];
        const rawLines = headerText.split("\n");

        for (const line of rawLines) {
            if (/^\s+/.test(line) && unfoldedLines.length > 0) {
                unfoldedLines[unfoldedLines.length - 1] += " " + line.trim();
            } else if (line.trim().length > 0) {
                unfoldedLines.push(line);
            }
        }

        const headers = {};
        const receivedHeaders = [];

        for (const line of unfoldedLines) {
            const colonIndex = line.indexOf(":");
            if (colonIndex !== -1) {
                const key = line.substring(0, colonIndex).trim();
                const value = line.substring(colonIndex + 1).trim();
                const lowerKey = key.toLowerCase();

                if (lowerKey === "received") {
                    receivedHeaders.push(value);
                } else {
                    headers[lowerKey] = value;
                }
            }
        }

        return {
            headers,
            receivedHeaders,
            body: bodyText,
            rawText
        };
    }

    /**
     * Extract Email Address & Display Name from formatted header value
     * Example: "State Bank of India" <support@sbi.co.in> -> { name: "State Bank of India", email: "support@sbi.co.in", domain: "sbi.co.in" }
     */
    extractAddressInfo(headerVal) {
        if (!headerVal) return { name: "", email: "", domain: "" };

        let name = "";
        let email = "";

        const match = headerVal.match(/(?:"?([^"]*)"?\s)?(?:<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?)/);
        if (match) {
            name = (match[1] || "").trim();
            email = (match[2] || "").trim();
        } else {
            email = headerVal.replace(/[<>]/g, "").trim();
        }

        const domain = email.includes("@") ? email.split("@")[1].toLowerCase() : "";
        return { name, email, domain };
    }

    /**
     * Extract IPv4 addresses from Received headers
     */
    extractIPsFromReceived(receivedList) {
        const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        const extractedHops = [];

        // Received headers are ordered top-to-bottom: Most recent (recipient) to earliest (origin)
        for (let i = 0; i < receivedList.length; i++) {
            const headerStr = receivedList[i];
            const matches = headerStr.match(ipRegex) || [];

            for (const ip of matches) {
                // Filter out private / loopback IP ranges
                if (!this.isPrivateIP(ip)) {
                    extractedHops.push({
                        hopIndex: receivedList.length - i,
                        ip: ip,
                        headerContext: headerStr.substring(0, 120) + "..."
                    });
                }
            }
        }

        // Reverse to get chronological mail routing: Origin (Hop 1) -> Intermediate Hops -> Recipient (Final Hop)
        return extractedHops.reverse();
    }

    /**
     * Check if an IP address is in private/loopback RFC 1918 space
     */
    isPrivateIP(ip) {
        if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("192.168.")) return true;
        if (ip.startsWith("172.")) {
            const secondOctet = parseInt(ip.split(".")[1], 10);
            if (secondOctet >= 16 && secondOctet <= 31) return true;
        }
        return false;
    }

    /**
     * Get GeoIP intelligence for an IP from database or fallback generator
     */
    getGeoIP(ip) {
        if (GEO_IP_DATABASE[ip]) {
            return { ...GEO_IP_DATABASE[ip] };
        }

        // Deterministic pseudo-lookup for unknown IPs during hackathon testing
        const hash = ip.split('.').reduce((acc, octet) => acc + parseInt(octet, 10), 0);
        const countries = [
            { city: "Frankfurt", country: "Germany", countryCode: "DE", lat: 50.1109, lng: 8.6821, isp: "Hetzner Online GmbH", asn: "AS24940" },
            { city: "London", country: "United Kingdom", countryCode: "GB", lat: 51.5074, lng: -0.1278, isp: "DigitalOcean LLC", asn: "AS14061" },
            { city: "Singapore", country: "Singapore", countryCode: "SG", lat: 1.3521, lng: 103.8198, isp: "OVH Hosting SG", asn: "AS16276" },
            { city: "San Jose", country: "United States", countryCode: "US", lat: 37.3382, lng: -121.8863, isp: "Equinix Direct", asn: "AS3356" }
        ];

        const choice = countries[hash % countries.length];
        return {
            ip,
            city: choice.city,
            region: "Regional Subnet",
            country: choice.country,
            countryCode: choice.countryCode,
            lat: choice.lat + (hash % 10) * 0.05,
            lng: choice.lng + (hash % 10) * 0.05,
            isp: choice.isp,
            asn: choice.asn,
            organization: choice.isp,
            proxy: hash % 3 === 0,
            vpn: hash % 4 === 0,
            tor: false,
            hosting: true,
            threatScore: (hash * 17) % 75,
            riskFactors: ["External Autonomous System"]
        };
    }

    /**
     * Get GeoIP intelligence enriched with threat intelligence data
     * @param {string} ip - IP address to check
     * @returns {Promise<Object>} Enhanced GeoIP data with threat intelligence
     */
    async getEnhancedGeoIP(ip) {
        const baseGeo = this.getGeoIP(ip);
        const threatIntel = await this.threatIntelManager.enrichIP(ip);
        // Merge the base geo with threat intelligence, giving precedence to threat intel for overlapping fields
        return { ...baseGeo, ...threatIntel };
    }

    /**
     * Validate SPF, DKIM, DMARC and Header Consistency
     */
    validateAuthentication(parsed) {
        const headers = parsed.headers;
        const fromInfo = this.extractAddressInfo(headers["from"]);
        const returnPathInfo = this.extractAddressInfo(headers["return-path"]);
        const replyToInfo = this.extractAddressInfo(headers["reply-to"]);
        const authResults = (headers["authentication-results"] || "").toLowerCase();
        const receivedSpf = (headers["received-spf"] || "").toLowerCase();

        let spfStatus = "PASS";
        let dkimStatus = "PASS";
        let dmarcStatus = "PASS";

        // SPF Check
        if (receivedSpf.includes("fail") || authResults.includes("spf=fail")) {
            spfStatus = "FAIL";
        } else if (receivedSpf.includes("softfail") || authResults.includes("spf=softfail")) {
            spfStatus = "SOFTFAIL";
        } else if (receivedSpf.includes("neutral") || authResults.includes("spf=neutral")) {
            spfStatus = "NEUTRAL";
        } else if (!receivedSpf && !authResults.includes("spf=")) {
            spfStatus = "NONE";
        }

        // DKIM Check
        if (authResults.includes("dkim=fail")) {
            dkimStatus = "FAIL";
        } else if (authResults.includes("dkim=neutral") || !headers["dkim-signature"]) {
            dkimStatus = "NONE";
        } else if (authResults.includes("dkim=pass") || headers["dkim-signature"]) {
            dkimStatus = "PASS";
        }

        // DMARC Check
        if (authResults.includes("dmarc=fail")) {
            dmarcStatus = "FAIL";
        } else if (authResults.includes("dmarc=pass")) {
            dmarcStatus = "PASS";
        } else {
            // Compute alignment: If From domain doesn't match Return-Path or DKIM failed
            if (fromInfo.domain && returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
                dmarcStatus = "FAIL";
            } else if (spfStatus === "FAIL" && dkimStatus !== "PASS") {
                dmarcStatus = "FAIL";
            }
        }

        // Alignment and Spoofing Flags
        const anomalies = [];
        let isSpoofed = false;

        if (fromInfo.domain && returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
            anomalies.push({
                type: "Return-Path Mismatch",
                severity: "HIGH",
                detail: `Display sender (@${fromInfo.domain}) differs from bounce return path (@${returnPathInfo.domain}). Classic indicator of domain spoofing.`
            });
            isSpoofed = true;
        }

        if (replyToInfo.email && fromInfo.email && replyToInfo.email.toLowerCase() !== fromInfo.email.toLowerCase()) {
            anomalies.push({
                type: "Reply-To Divergence",
                severity: "MEDIUM",
                detail: `Replies are routed to "${replyToInfo.email}" instead of the visible sender "${fromInfo.email}".`
            });
        }

        if (headers["message-id"]) {
            const msgIdDomain = (headers["message-id"].split("@")[1] || "").replace(/[>]/g, "").trim().toLowerCase();
            if (fromInfo.domain && msgIdDomain && !msgIdDomain.includes(fromInfo.domain) && !msgIdDomain.includes("google") && !msgIdDomain.includes("amazonses")) {
                anomalies.push({
                    type: "Message-ID Infrastructure Discrepancy",
                    severity: "MEDIUM",
                    detail: `Message-ID was generated by host "@${msgIdDomain}" which does not match claimed sender organization "@${fromInfo.domain}".`
                });
            }
        }

        return {
            from: fromInfo,
            returnPath: returnPathInfo,
            replyTo: replyToInfo,
            spf: { status: spfStatus, details: receivedSpf || "Evaluated via Authentication-Results" },
            dkim: { status: dkimStatus, selector: (headers["dkim-signature"] || "").match(/s=([a-zA-Z0-9]+)/)?.[1] || "default" },
            dmarc: { status: dmarcStatus, policy: authResults.includes("p=reject") ? "REJECT" : "NONE" },
            anomalies,
            isSpoofed
        };
    }

    /**
     * AI & NLP Content Analysis for Phishing, Urgency, Credential Theft & BEC
     * Enhanced with pattern-based detection for more accurate threat identification
     */
    analyzeNLPContent(subject, body) {
        const fullText = (subject + " " + body).toLowerCase();

        let urgencyScore = 0;
        const matchedUrgency = [];

        // Check urgency patterns
        for (const pattern of this.urgencyPatterns) {
            const matches = fullText.match(pattern);
            if (matches) {
                urgencyScore += Math.min(15 * matches.length, 15); // Cap per pattern type
                matchedUrgency.push(...matches);
            }
        }

        // Also check original keywords for backward compatibility
        for (const kw of this.urgencyKeywords) {
            if (fullText.includes(kw) && !matchedUrgency.includes(kw)) {
                urgencyScore += 10;
                matchedUrgency.push(kw);
            }
        }

        let financialScore = 0;
        const matchedFinancial = [];

        // Check financial patterns
        for (const pattern of this.financialPatterns) {
            const matches = fullText.match(pattern);
            if (matches) {
                financialScore += Math.min(15 * matches.length, 15);
                matchedFinancial.push(...matches);
            }
        }

        // Also check original keywords
        for (const kw of this.financialKeywords) {
            if (fullText.includes(kw) && !matchedFinancial.includes(kw)) {
                financialScore += 10;
                matchedFinancial.push(kw);
            }
        }

        let credentialScore = 0;
        const matchedCredentials = [];

        // Check credential patterns
        for (const pattern of this.credentialPatterns) {
            const matches = fullText.match(pattern);
            if (matches) {
                credentialScore += Math.min(20 * matches.length, 20);
                matchedCredentials.push(...matches);
            }
        }

        // Also check original keywords
        for (const kw of this.credentialKeywords) {
            if (fullText.includes(kw) && !matchedCredentials.includes(kw)) {
                credentialScore += 10;
                matchedCredentials.push(kw);
            }
        }

        // Enhanced BEC detection with pattern matching
        let isBEC = false;
        const becIndicators = [
            /\b(?:ceo|chief\s+executive|executive\s+director|president|vice\s+president|cfo|chief\s+financial\s+officer)\b/i,
            /\b(?:board\s+meeting|executive\s+session|confidential\s+meeting|closed\s+door)\b/i,
            /\b(?:acquisition|merger|takeover|buyout|purchase\s+agreement)\b/i,
            /\b(?:nda[-\s]?restricted|non[-\s]?disclosure|proprietary\s+information|confidential\s+and\s+urgent)\b/i,
            /\b(?:wire\s+transfer|bank\s+transfer|swift\s+payment|escrow\s+account)\b/i,
            /\b(?:foreign\s+exchange|fx\s+transaction|cutoff\s+(?:time|date|rate))\b/i,
            /\b(?:benefiary\s+(?:details|information|account|name|routing))\b/i
        ];

        becIndicators.forEach(pattern => {
            if (fullText.match(pattern)) {
                isBEC = true;
            }
        });

        // Also check for urgency + financial combination (classic BEC)
        if (urgencyScore >= 25 && financialScore >= 25) {
            isBEC = true;
        }

        // Detect Malicious / Phishing URLs & Obfuscations
        const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
        const extractedUrls = body.match(urlRegex) || [];
        const suspiciousUrls = [];

        for (const url of extractedUrls) {
            let risk = "LOW";
            let reason = "Standard web link";

            // Check for raw IP in URL
            if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i.test(url)) {
                risk = "CRITICAL";
                reason = "Direct IP Address link bypassing domain security filters.";
            }
            // Check for suspicious TLDs
            else if (/\.(ru|xyz|top|tk|cn|cc|to|live)\b/i.test(url)) {
                risk = "HIGH";
                reason = "Link points to high-risk top-level domain frequently used in disposable phishing.";
            }
            // Check for URL shorteners (often used in phishing)
            else if (/\bit\.ly\/|bit\.ly\/|tinyurl\.com\/|t\.co\/|goo\.gl\/|ow\.ly\/|is\.gd\/|buff\.ly\/|adf\.ly\/|bitly\.com\/|tinyurl\.com\/|tr\.im\/|cli\.gs\/|wb\.lnk\/|cutt\.ly\/|short\/|buff\.ly\/|linktiger\.net\//i.test(url)) {
                risk = "MEDIUM";
                reason = "URL shortener service - common in phishing to hide malicious destinations.";
            }
            // Check lookalikes
            else {
                for (const item of this.typosquatDatabase) {
                    for (const lookalike of item.lookalikes) {
                        if (url.toLowerCase().includes(lookalike)) {
                            risk = "CRITICAL";
                            reason = `Typosquatted lookalike of legitimate brand "${item.legitimate}".`;
                            break;
                        }
                    }
                    if (risk === "CRITICAL") break;
                }
            }

            suspiciousUrls.push({ url, risk, reason });
        }

        // Brand impersonation detection in body
        let brandImpersonationScore = 0;
        const brandMatches = [];
        for (const pattern of this.brandImpersonationPatterns) {
            const matches = fullText.match(pattern);
            if (matches) {
                brandImpersonationScore += Math.min(10 * matches.length, 15);
                brandMatches.push(...matches.map(m => m.toLowerCase()));
            }
        }

        // If brand mentioned in body but domain doesn't match, increase suspicion
        const senderDomain = this.extractAddressInfo(subject || "").domain || "";
        if (brandImpersonationScore > 0 && senderDomain) {
            const brandInBody = brandMatches.some(brand =>
                this.typosquatDatabase.some(item =>
                    item.legitimate.toLowerCase().includes(brand) ||
                    brand.includes(item.legitimate.toLowerCase())
                )
            );

            if (brandInBody && senderDomain &&
                !this.typosquatDatabase.some(item =>
                    item.legitimate.toLowerCase() === senderDomain.toLowerCase() ||
                    senderDomain.toLowerCase().includes(item.legitimate.toLowerCase())
                )) {
                // Brand mentioned in body but sender domain doesn't match - potential impersonation
                brandImpersonationScore = Math.min(brandImpersonationScore + 15, 30);
            }
        }

        return {
            urgencyScore: Math.min(urgencyScore, 100),
            financialScore: Math.min(financialScore, 100),
            credentialScore: Math.min(credentialScore, 100),
            brandImpersonationScore: Math.min(brandImpersonationScore, 30),
            matchedUrgency: [...new Set(matchedUrgency)],
            matchedFinancial: [...new Set(matchedFinancial)],
            matchedCredentials: [...new Set(matchedCredentials)],
            matchedBrands: [...new Set(brandMatches)],
            isBEC,
            extractedUrls: suspiciousUrls
        };
    }

    /**
     * Compute Overall Threat Score (0 - 100) and Verdict
     * Enhanced with AI-driven pattern detection
     */
    calculateOverallThreat(auth, nlp, hops, originGeo) {
        let score = 0;
        const threatFactors = [];

        // 1. Authentication & Spoofing Penalties (Max 40 pts)
        if (auth.dmarc.status === "FAIL") {
            score += 25;
            threatFactors.push("DMARC Alignment Verification Failed");
        }
        if (auth.spf.status === "FAIL" || auth.spf.status === "SOFTFAIL") {
            score += 15;
            threatFactors.push(`SPF Authentication ${auth.spf.status}`);
        }
        if (auth.isSpoofed) {
            score += 15;
            threatFactors.push("Return-Path vs From Domain Spoof Detected");
        }
        if (auth.dkim.status === "FAIL") {
            score += 10;
            threatFactors.push("Cryptographic DKIM Signature Invalid");
        }

        // 2. NLP & Social Engineering Risk (Max 45 pts - increased for enhanced detection)
        if (nlp.isBEC) {
            score += 30;
            threatFactors.push("High-Confidence Business Email Compromise (BEC) Signature");
        }
        if (nlp.credentialScore >= 35) {
            score += 25;
            threatFactors.push("Aggressive Credential Harvesting & Account Coercion Patterns");
        } else if (nlp.urgencyScore >= 30) {
            score += 15;
            threatFactors.push("Psychological Urgency & Artificial Deadline Pressure");
        }

        // Brand impersonation detection (new AI-driven feature)
        if (nlp.brandImpersonationScore >= 20) {
            score += 20;
            threatFactors.push("Brand Impersonation Detected in Email Body");
        } else if (nlp.brandImpersonationScore >= 10) {
            score += 10;
            threatFactors.push("Potential Brand Reference Anomaly");
        }

        // Combined urgency+financial threat (enhanced BEC detection)
        if (nlp.urgencyScore >= 25 && nlp.financialScore >= 25) {
            score += 20; // Additional points for classic BEC pattern
            threatFactors.push("Urgency-Financial Pressure Combination (BEC Indicator)");
        }

        // 3. Infrastructure & GeoIP Risk (Max 25 pts)
        if (originGeo) {
            if (originGeo.tor) {
                score += 25;
                threatFactors.push("Originating Node is a Known TOR Anonymity Exit Relay");
            } else if (originGeo.vpn || originGeo.proxy) {
                score += 15;
                threatFactors.push("Originating IP routed through Proxy / VPN Gateway");
            }
            if (originGeo.riskFactors && originGeo.riskFactors.length > 0) {
                score += 10;
                threatFactors.push(...originGeo.riskFactors);
            }
        }

        // 4. URL Threat Penalty
        const criticalUrls = nlp.extractedUrls.filter(u => u.risk === "CRITICAL" || u.risk === "HIGH");
        if (criticalUrls.length > 0) {
            score += 25;
            threatFactors.push(`Discovered ${criticalUrls.length} Malicious / Typosquatted URLs in Body`);
        }

        score = Math.min(Math.max(score, 0), 100);

        let verdict = "CLEAN";
        let threatColor = "var(--threat-clean)";
        let category = "Legitimate Verified Communication";

        if (score >= 75) {
            verdict = "CRITICAL";
            threatColor = "var(--threat-critical)";
            // Enhanced categorization with AI-driven insights
            if (nlp.isBEC) {
                category = "Business Email Compromise (BEC)";
            } else if (nlp.brandImpersonationScore >= 15) {
                category = "Brand Impersonation / Phishing Attack";
            } else if (nlp.credentialScore >= 30) {
                category = "Phishing Credential Harvester";
            } else {
                category = "Active Email Fraud Attack";
            }
        } else if (score >= 50) {
            verdict = "HIGH";
            threatColor = "var(--threat-high)";
            if (nlp.brandImpersonationScore >= 10) {
                category = "Likely Brand Impersonation Attempt";
            } else {
                category = "Suspicious Impersonation / Lookalike Domain";
            }
        } else if (score >= 25) {
            verdict = "MEDIUM";
            threatColor = "var(--threat-medium)";
            category = "Policy Misconfiguration / Unverified Relay";
        }

        // Determine email type based on threat score
        let emailType = "LEGITIMATE";
        if (score >= 50) {
            emailType = "SCAM";
        } else if (score >= 25) {
            emailType = "SPAM";
        }

        return {
            score,
            verdict,
            threatColor,
            category,
            threatFactors: [...new Set(threatFactors)],
            emailType
        };
    }

    /**
     * Cryptographic Evidence Hash Calculation using Web Crypto API
     */
    async calculateHashes(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        // SHA-256
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const sha256 = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

        // Simple Fast CRC32 / MD5 simulation for forensic display
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        const md5Sim = Math.abs(hash).toString(16).padStart(16, "0") + "4f8a9e2b1c7d";

        return {
            sha256,
            md5: md5Sim,
            payloadLength: text.length,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Master Forensic Scan Pipeline
     */
    async executeForensicScan(rawEmailText) {
        // Step 1: RFC 5322 Parsing
        const parsed = this.parseEmail(rawEmailText);

        // Step 2: Extract Relay Hops & GeoIP Data
        const rawHops = this.extractIPsFromReceived(parsed.receivedHeaders);
        const hops = rawHops.map((hop, index) => {
            const geo = this.getGeoIP(hop.ip);
            return {
                hopNumber: index + 1,
                ip: hop.ip,
                geo,
                context: hop.headerContext
            };
        });

        // Originating Server is Hop 1 (earliest recorded public transmission node)
        const originHop = hops.length > 0 ? hops[0] : null;
        let originGeo = originHop ? originHop.geo : null;

        // Step 3: Header & Authentication Validation
        const auth = this.validateAuthentication(parsed);

        // Step 4: NLP Linguistic Analysis
        const nlp = this.analyzeNLPContent(parsed.headers["subject"] || "", parsed.body);

        // Step 5: Composite Threat Scoring
        const threatSummary = this.calculateOverallThreat(auth, nlp, hops, originGeo);

        // Step 6: Enhance origin GeoIP with threat intelligence
        if (originGeo) {
            const enhancedOriginGeo = await this.getEnhancedGeoIP(originGeo.ip);
            // Update the originHop's geo and also the originGeo variable
            originHop.geo = enhancedOriginGeo;
            originGeo = enhancedOriginGeo;
        }

        // Step 7: Evidence Integrity Hashing
        const hashes = await this.calculateHashes(rawEmailText);

        // Step 8: Forensic Attribution Vector Graph
        const attributionGraph = this.buildAttributionGraph(auth, nlp, originGeo, hops);

        return {
            parsed,
            hops,
            originHop,
            originGeo,
            auth,
            nlp,
            threatSummary,
            hashes,
            attributionGraph,
            analyzedAt: new Date().toLocaleString()
        };
    }

    /**
     * Build Graph Nodes & Links for Visual Attribution Model
     */
    buildAttributionGraph(auth, nlp, originGeo, hops) {
        const nodes = [];
        const links = [];

        // 1. Origin Node (Threat Infrastructure or Legitimate Origin)
        const originLabel = originGeo ? `${originGeo.city}, ${originGeo.countryCode}` : "Unknown Sender Node";
        const originIsMalicious = originGeo ? (originGeo.threatScore > 50 || originGeo.tor || originGeo.vpn) : false;

        nodes.push({
            id: "origin",
            label: `Origin: ${originGeo ? originGeo.ip : "Direct Host"}`,
            sub: originLabel,
            type: originIsMalicious ? "attacker" : "trusted",
            icon: originGeo && originGeo.tor ? "🧅" : (originGeo && originGeo.vpn ? "🛡️" : "🖥️")
        });

        // 2. Intermediate Relay Hops
        hops.forEach((hop, i) => {
            const hopNodeId = `hop_${i + 1}`;
            nodes.push({
                id: hopNodeId,
                label: `Hop ${i + 1}: ${hop.geo.city}`,
                sub: hop.geo.isp.substring(0, 20),
                type: "relay",
                icon: "🔄"
            });

            if (i === 0) {
                links.push({ source: "origin", target: hopNodeId, label: "Transmitted From" });
            } else {
                links.push({ source: `hop_${i}`, target: hopNodeId, label: "Relayed via" });
            }
        });

        // 3. Sender Identity / Domain
        const senderDomain = auth.from.domain || "Unknown Domain";
        nodes.push({
            id: "sender_identity",
            label: auth.from.name || senderDomain,
            sub: auth.isSpoofed ? "⚠️ Spoofed Identity" : "Verified Identity",
            type: auth.isSpoofed ? "spoof" : "identity",
            icon: auth.isSpoofed ? "🎭" : "👤"
        });

        const lastHopId = hops.length > 0 ? `hop_${hops.length}` : "origin";
        links.push({ source: lastHopId, target: "sender_identity", label: "Claims From" });

        // 4. Target Victim Node
        nodes.push({
            id: "victim",
            label: "Target Organization",
            sub: `${VICTIM_ORGANIZATION_ENDPOINT.city}, ${VICTIM_ORGANIZATION_ENDPOINT.country}`,
            type: "victim",
            icon: "🎯"
        });

        links.push({ source: "sender_identity", target: "victim", label: "Delivered To" });

        return { nodes, links };
    }

    /**
     * Helper function to extract keywords from text for similarity matching
     * @param {string} text - Text to extract keywords from
     * @returns {Set<string>} - Set of significant keywords
     */
    extractKeywords(text) {
        if (!text) return new Set();

        // Convert to lowercase and split by non-alphanumeric characters
        const words = text.toLowerCase().split(/[^a-zA-Z0-9]+/);
        const keywords = new Set();

        for (const word of words) {
            // Skip short words, numbers, and stop words
            if (word.length >= 3 && !/^\d+$/.test(word) && !this.stopWords.has(word)) {
                keywords.add(word);
            }
        }

        return keywords;
    }

    /**
     * Calculate Jaccard similarity between two sets
     * @param {Set<any>} setA - First set
     * @param {Set<any>} setB - Second set
     * @returns {number} - Similarity score between 0 and 1
     */
    jaccardSimilarity(setA, setB) {
        if (!setA || !setB) return 0;

        const intersection = new Set([...setA].filter(x => setB.has(x)));
        const union = new Set([...setA, ...setB]);

        return union.size === 0 ? 0 : intersection.size / union.size;
    }

    /**
     * Calculate similarity between two cases for campaign grouping
     * @param {Object} caseA - First case object
     * @param {Object} caseB - Second case object
     * @returns {number} - Similarity score between 0 and 1
     */
    calculateCaseSimilarity(caseA, caseB) {
        let score = 0;
        const weights = {
            senderDomain: 0.25,    // 25% weight
            subjectSimilarity: 0.25, // 25% weight
            originASN: 0.20,       // 20% weight
            threatCategory: 0.15,  // 15% weight
            threatVerdict: 0.15    // 15% weight
        };

        // Sender domain similarity (exact match)
        if (caseA.senderDomain && caseB.senderDomain) {
            if (caseA.senderDomain.toLowerCase() === caseB.senderDomain.toLowerCase()) {
                score += weights.senderDomain;
            }
        }

        // Subject line similarity using keyword Jaccard
        if (caseA.subjectKeywords && caseB.subjectKeywords) {
            const subjectSim = this.jaccardSimilarity(caseA.subjectKeywords, caseB.subjectKeywords);
            score += weights.subjectSimilarity * subjectSim;
        }

        // Origin ASN similarity (exact match)
        if (caseA.originASN && caseB.originASN) {
            if (caseA.originASN === caseB.originASN) {
                score += weights.originASN;
            }
        }

        // Threat category similarity
        if (caseA.threatCategory && caseB.threatCategory) {
            if (caseA.threatCategory === caseB.threatCategory) {
                score += weights.threatCategory;
            }
        }

        // Threat verdict similarity
        if (caseA.threatVerdict && caseB.threatVerdict) {
            if (caseA.threatVerdict === caseB.threatVerdict) {
                score += weights.threatVerdict;
            }
        }

        return Math.min(score, 1.0); // Cap at 1.0
    }
}

// Global Engine Instance
window.forensicEngine = new ForensicEngine();