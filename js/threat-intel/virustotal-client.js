/**
 * VirusTotal Threat Intelligence Client
 * Provides IP reputation data including malware detections, URL scanning results, and threat ratings
 */
class VirusTotalClient {
    constructor(apiKey = null) {
        this.apiKey = apiKey || '';
        this.baseUrl = 'https://www.virustotal.com/api/v3';
        this.cache = new Map();
        this.cacheTimeout = 15 * 60 * 1000; // 15 minutes
        this.lastRequestTime = 0;
        this.minRequestInterval = 15000; // 15 seconds between requests (VT rate limit: 4 req/min for free tier)
    }

    /**
     * Check IP address for threat intelligence
     * @param {string} ip - IP address to check
     * @returns {Promise<Object>} Threat intelligence data
     */
    async checkIP(ip) {
        // Validate IP format
        if (!this.isValidIP(ip)) {
            return this.getDefaultResponse(ip);
        }

        // Check cache first
        const cached = this.getFromCache(ip);
        if (cached) {
            return cached;
        }

        // Rate limiting for VirusTotal (4 requests per minute for free tier)
        await this.enforceRateLimit();

        try {
            // If no API key, return mock data for demo
            if (!this.apiKey) {
                return this.getMockData(ip);
            }

            const response = await fetch(`${this.baseUrl}/ip_addresses/${ip}`, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKey
                }
            });

            if (!response.ok) {
                // Handle specific error cases
                if (response.status === 404) {
                    // IP not found in VT database - treat as clean
                    return this.getNotFoundResponse(ip);
                }
                throw new Error(`VirusTotal API error: ${response.status}`);
            }

            const data = await response.json();
            const result = this.normalizeResponse(data.data);
            this.saveToCache(ip, result);
            return result;
        } catch (error) {
            console.warn('VirusTotal API failed, using mock data:', error);
            return this.getMockData(ip);
        }
    }

    /**
     * Normalize VirusTotal response to common format
     * @param {Object} data - Raw API response data
     * @returns {Object} Normalized threat intelligence
     */
    normalizeResponse(data) {
        const attributes = data.attributes || {};
        const lastAnalysisStats = attributes.last_analysis_stats || {};
        const lastAnalysisResults = attributes.last_analysis_results || {};

        // Calculate threat score based on malicious vs total engines
        const malicious = lastAnalysisStats.malicious || 0;
        const suspicious = lastAnalysisStats.suspicious || 0;
        const harmless = lastAnalysisStats.harmless || 0;
        const undetected = lastAnalysisStats.undetected || 0;
        const total = malicious + suspicious + harmless + undetected;

        let threatScore = 0;
        if (total > 0) {
            // Weighted score: malicious counts double, suspicious counts 1.5x
            const weightedScore = (malicious * 2 + suspicious * 1.5) / (total * 2) * 100;
            threatScore = Math.min(Math.round(weightedScore), 100);
        }

        // Extract malware tags from positive detections
        const malwareTags = this.extractMalwareTags(lastAnalysisResults);

        // Extract threat description based on analysis
        const { threatDescription, recommendedAction } = this.getThreatAssessment(
            threatScore,
            malicious,
            suspicious,
            attributes
        );

        return {
            abuseConfidence: threatScore, // VT doesn't have abuse confidence, use threat score
            threatScore: threatScore,
            malwareTags: malwareTags,
            botnetFamilies: this.extractBotnetFamilies(lastAnalysisResults),
            lastReported: attributes.last_analysis_date ?
                new Date(attributes.last_analysis_date * 1000).toISOString() :
                null,
            totalReports: malicious + suspicious, // VT doesn't have report count, use detections
            ispReputation: this.getISPReputation(attributes.as_owner, attributes.network),
            threatDescription: threatDescription,
            recommendedAction: recommendedAction,
            // Additional useful data from VT
            ip: data.id,
            asn: attributes.asn || '',
            asOwner: attributes.as_owner || '',
            country: attributes.country || '',
            network: attributes.network || '',
            whois: attributes.whois || '',
            // VT-specific stats
            harmlessVotes: lastAnalysisStats.harmless || 0,
            maliciousVotes: lastAnalysisStats.malicious || 0,
            suspiciousVotes: lastAnalysisStats.suspicious || 0,
            undetectedVotes: lastAnalysisStats.undetected || 0,
            timeoutVotes: lastAnalysisStats.timeout || 0
        };
    }

    /**
     * Extract malware tags from VirusTotal analysis results
     * @param {Object} results - Last analysis results from VT
     * @returns {string[]} Malware tags
     */
    extractMalwareTags(results) {
        const tags = new Set();

        for (const [engineName, result] of Object.entries(results)) {
            if (result.category === 'malicious' || result.category === 'suspicious') {
                // Add the detection name as a tag
                if (result.result) {
                    tags.add(result.result);
                }
                // Add engine name as context
                tags.add(`Detected_by_${engineName}`);
            }
        }

        // Limit to reasonable number for display
        const tagArray = Array.from(tags);
        return tagArray.slice(0, 10); // Max 10 tags
    }

    /**
     * Extract potential botnet families from analysis results
     * @param {Object} results - Last analysis results from VT
     * @returns {string[]} Botnet families
     */
    extractBotnetFamilies(results) {
        const families = new Set();
        const botnetKeywords = [
            'botnet', 'bot', 'c2', 'command', 'control',
            'zeus', 'mirai', 'cutwail', 'pushdo',
            'emotet', 'trickbot', 'cobaltstrike', 'rat'
        ];

        for (const [engineName, result] of Object.entries(results)) {
            if (result.category === 'malicious' || result.category === 'suspicious') {
                const resultText = (result.result || '').toLowerCase();
                const engineText = engineName.toLowerCase();

                for (const keyword of botnetKeywords) {
                    if (resultText.includes(keyword) || engineText.includes(keyword)) {
                        families.add(result.result || engineName);
                    }
                }
            }
        }

        return Array.from(families).slice(0, 5); // Max 5 botnet families
    }

    /**
     * Get threat description and recommended action based on analysis
     * @param {number} threatScore - Calculated threat score (0-100)
     * @param {number} malicious - Number of engines detecting as malicious
     * @param {number} suspicious - Number of engines detecting as suspicious
     * @param {Object} attributes - VT response attributes
     * @returns {Object} threatDescription and recommendedAction
     */
    getThreatAssessment(threatScore, malicious, suspicious, attributes) {
        let threatDescription, recommendedAction;

        if (threatScore >= 80) {
            threatDescription = 'High-confirmed malicious IP - Multiple security engines detect threats';
            recommendedAction = 'BLOCK IMMEDIATELY - High confidence malicious IP';
        } else if (threatScore >= 60) {
            threatDescription = 'Likely malicious IP - Significant security engine detections';
            recommendedAction = 'BLOCK - Strong indicators of malicious activity';
        } else if (threatScore >= 30) {
            threatDescription = 'Suspicious IP - Some security engines flag as potentially malicious';
            recommendedAction = 'MONITOR CLOSELY - Investigate further before allowing';
        } else if (threatScore > 0) {
            threatDescription = 'Low-risk IP - Minimal security engine detections';
            recommendedAction = 'MONITOR - Minimal threat indicators, watch for changes';
        } else {
            threatDescription = 'Clean IP - No security engines detect threats';
            recommendedAction = 'APPEARS CLEAN - No significant threat intelligence from VT';
        }

        // Add context about detection rates if available
        const totalEngines = malicious + suspicious + (attributes.last_analysis_stats?.harmless || 0) +
                           (attributes.last_analysis_stats?.undetected || 0);
        if (totalEngines > 0) {
            const detectionRate = ((malicious + suspicious) / totalEngines * 100).toFixed(1);
            threatDescription += ` (${detectionRate}% of engines detected threats)`;
        }

        return { threatDescription, recommendedAction };
    }

    /**
     * Determine ISP reputation based on AS owner and network data
     * @param {string} asOwner - AS owner organization
     * @param {string} network - Network information
     * @returns {string} Reputation level
     */
    getISPReputation(asOwner, network) {
        if (!asOwner) return 'unknown';

        const asOwnerLower = asOwner.toLowerCase();
        const networkLower = network ? network.toLowerCase() : '';

        // Known bad hosting/AS providers (for demo)
        const badHosting = ['bulletproof', 'anonym', 'offshore', 'bullet', 'privacy', 'bulletproof'];
        const badASNs = ['selectel', 'miranda', 'zwiebelfreunde', 'hostroyale', 'vps', 'cheap'];

        if (badHosting.some(h => asOwnerLower.includes(h)) ||
            badASNs.some(b => asOwnerLower.includes(b))) {
            return 'poor';
        }

        // Known good ISPs/cloud providers
        const goodProviders = ['google', 'cloudflare', 'amazon', 'microsoft', 'digitalocean',
                              'hetzner', 'ovh', 'linode', 'vultr', 'aws', 'azure'];
        if (goodProviders.some(g => asOwnerLower.includes(g))) {
            return 'excellent';
        }

        return 'neutral';
    }

    /**
     * Get mock data for demo when API is unavailable
     * @param {string} ip - IP address
     * @returns {Object} Mock threat intelligence data
     */
    getMockData(ip) {
        // Generate deterministic mock data based on IP hash
        const hash = ip.split('.').reduce((acc, octet) => acc + parseInt(octet, 10), 0);
        const maliciousVotes = (hash * 17) % 70; // 0-69 malicious votes
        const suspiciousVotes = (hash * 13) % 30; // 0-29 suspicious votes
        const harmlessVotes = 50 + ((hash * 19) % 40); // 50-89 harmless votes
        const undetectedVotes = 100 - (maliciousVotes + suspiciousVotes + harmlessVotes);
        const total = maliciousVotes + suspiciousVotes + harmlessVotes + undetectedVotes;

        // Calculate threat score (weighted: malicious*2 + suspicious*1.5)
        const weightedScore = ((maliciousVotes * 2) + (suspiciousVotes * 1.5)) / (total * 2) * 100;
        const threatScore = Math.min(Math.round(weightedScore), 100);

        const malwareOptions = [
            ['Trojan.Win32.Generic', 'Phish.Agent', 'Banker.Trojan'],
            ['Win32/Zeus', 'Win32/SpyEye', 'HTML/Phishing'],
            ['Linux/Mirai', 'Linux/Gafgyt', 'ELF/Bot'],
            ['JS/Emotet', 'JS/Trickbot', 'VBS/Dridex'],
            ['PE/CobaltStrike', 'PE/Metasploit', 'PDF/Exploit']
        ];
        const malwareTags = malwareOptions[hash % malwareOptions.length];

        const botnetOptions = [
            ['Cutwail', 'Pushdo', 'Spambot'],
            ['Zeus', 'SpyEye', 'Banker'],
            ['Mirai', 'Hajime', 'IoT_Botnet'],
            ['Konziz', 'Ramnit', 'FileInfector'],
            ['Conficker', 'Sality', 'Virut']
        ];
        const botnetFamilies = botnetOptions[hash % botnetOptions.length];

        const lastAnalysisDate = Date.now() - (hash % 15) * 24 * 60 * 60 * 1000; // 0-14 days ago

        const threatDescriptions = [
            'IP associated with malware distribution and command & control',
            'Hosting service abused for phishing and malware campaigns',
            'Compromised server used in botnet infrastructure',
            'IP address linked to spam and malicious hosting',
            'Server involved in financial fraud and credential theft'
        ];
        const threatDescription = threatDescriptions[hash % threatDescriptions.length];

        const recommendedActions = [
            'BLOCK IMMEDIATELY - High confidence malicious IP',
            'BLOCK - Multiple security vendors flag as malicious',
            'MONITOR CLOSELY - Some suspicious activity detected',
            'MONITOR - Minimal threat indicators, continue observation',
            'APPEARS CLEAN - No significant threat intelligence from security vendors'
        ];
        const recommendedAction = recommendedActions[Math.min(Math.floor(threatScore / 25), 4)];

        return {
            abuseConfidence: threatScore,
            threatScore: threatScore,
            malwareTags: malwareTags,
            botnetFamilies: botnetFamilies,
            lastReported: new Date(lastAnalysisDate).toISOString(),
            totalReports: maliciousVotes + suspiciousVotes,
            ispReputation: ['excellent', 'good', 'neutral', 'poor', 'terrible'][Math.floor(hash / 50) % 5],
            threatDescription: threatDescription,
            recommendedAction: recommendedAction,
            ip: ip,
            asn: `AS${200000 + (hash % 50000)}`,
            asOwner: ['Selectel', 'Miranda Media', 'Hetzner', 'DigitalOcean', 'OVH', 'Google', 'Amazon'][hash % 7] || 'Unknown AS',
            country: ['US', 'RU', 'CN', 'DE', 'GB', 'NL'][hash % 6] || '',
            network: ['Hosting Network', 'ISP Network', 'Corporate Network', 'Mobile Network', 'VPN Network'][hash % 5],
            whois: 'Registrar: Example Registrar, Inc.\\nCreation Date: 2020-01-01\\nExpiration Date: 2025-01-01',
            harmlessVotes: harmlessVotes,
            maliciousVotes: maliciousVotes,
            suspiciousVotes: suspiciousVotes,
            undetectedVotes: undetectedVotes,
            timeoutVotes: Math.floor(hash % 10)
        };
    }

    /**
     * Get response for IP not found in VirusTotal database
     * @param {string} ip - IP address
     * @returns {Object} Response for unknown IP
     */
    getNotFoundResponse(ip) {
        return {
            abuseConfidence: 0,
            threatScore: 5, // Low score for unknown (could be new or clean)
            malwareTags: [],
            botnetFamilies: [],
            lastReported: null,
            totalReports: 0,
            ispReputation: 'unknown',
            threatDescription: 'IP address not found in VirusTotal database',
            recommendedAction: 'CHECK MANUALLY - IP not in VT database, consider other sources',
            ip: ip,
            asn: '',
            asOwner: '',
            country: '',
            network: '',
            whois: '',
            harmlessVotes: 0,
            maliciousVotes: 0,
            suspiciousVotes: 0,
            undetectedVotes: 0,
            timeoutVotes: 0
        };
    }

    /**
     * Get default response for invalid IP
     * @param {string} ip - IP address
     * @returns {Object} Default response
     */
    getDefaultResponse(ip) {
        return {
            abuseConfidence: 0,
            threatScore: 0,
            malwareTags: [],
            botnetFamilies: [],
            lastReported: null,
            totalReports: 0,
            ispReputation: 'unknown',
            threatDescription: 'Invalid IP address format',
            recommendedAction: 'IGNORE - Not a valid IP address',
            ip: ip,
            asn: '',
            asOwner: '',
            country: '',
            network: '',
            whois: '',
            harmlessVotes: 0,
            maliciousVotes: 0,
            suspiciousVotes: 0,
            undetectedVotes: 0,
            timeoutVotes: 0
        };
    }

    /**
     * Check if string is valid IPv4 address
     * @param {string} ip - String to validate
     * @returns {boolean} True if valid IPv4
     */
    isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipv4Regex.test(ip);
    }

    /**
     * Get data from cache if not expired
     * @param {string} ip - IP address
     * @returns {Object|null} Cached data or null
     */
    getFromCache(ip) {
        const cached = this.cache.get(ip);
        if (!cached) return null;

        if (Date.now() - cached.timestamp > this.cacheTimeout) {
            this.cache.delete(ip);
            return null;
        }

        return cached.data;
    }

    /**
     * Save data to cache
     * @param {string} ip - IP address
     * @param {Object} data - Data to cache
     */
    saveToCache(ip, data) {
        this.cache.set(ip, {
            data: data,
            timestamp: Date.now()
        });

        // Limit cache size to prevent memory leaks
        if (this.cache.size > 500) {
            // Remove oldest entry
            const oldestKey = Array.from(this.cache.keys()).reduce((a, b) =>
                this.cache.get(a).timestamp < this.cache.get(b).timestamp ? a : b
            );
            this.cache.delete(oldestKey);
        }
    }

    /**
     * Enforce rate limiting between requests
     */
    async enforceRateLimit() {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;

        if (timeSinceLastRequest < this.minRequestInterval) {
            await new Promise(resolve =>
                setTimeout(resolve, this.minRequestInterval - timeSinceLastRequest)
            );
        }

        this.lastRequestTime = Date.now();
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VirusTotalClient;
} else {
    window.VirusTotalClient = VirusTotalClient;
}