/**
 * Threat Intelligence Manager
 * Coordinates multiple threat intelligence providers and provides unified interface
 */
class ThreatIntelManager {
    constructor() {
        // Initialize clients (API keys would come from config/environment in production)
        this.abuseIPDB = new AbuseIPDBClient();
        this.virusTotal = new VirusTotalClient();
        this.otx = new OTXClient();

        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes for merged results

        // Weighting for different threat intelligence sources in final score
        this.sourceWeights = {
            abuseIPDB: 0.4,   // 40% weight - good for abuse/reputation data
            virusTotal: 0.35, // 35% weight - good for malware/anti-virus data
            otx: 0.25         // 25% weight - good for pulse/threat actor data
        };
    }

    /**
     * Get enriched threat intelligence for an IP address from all sources
     * @param {string} ip - IP address to check
     * @returns {Promise<Object>} Unified threat intelligence data
     */
    async enrichIP(ip) {
        // Validate IP format
        if (!this.isValidIP(ip)) {
            return this.getDefaultResponse(ip);
        }

        // Check cache first
        const cached = this.getFromCache(ip);
        if (cached) {
            return cached;
        }

        try {
            // Fetch from all sources in parallel
            const [abuseData, vtData, otxData] = await Promise.all([
                this.abuseIPDB.checkIP(ip),
                this.virusTotal.checkIP(ip),
                this.otx.getPulseInfo(ip)
            ]);

            // Merge and normalize the data
            const mergedData = this.mergeThreatIntelData(abuseData, vtData, otxData);

            // Save to cache
            this.saveToCache(ip, mergedData);

            return mergedData;
        } catch (error) {
            console.error('Error in threat intelligence enrichment:', error);
            // Fallback to abuseIPDB only if others fail
            try {
                const abuseData = await this.abuseIPDB.checkIP(ip);
                return this.getDefaultEnrichment(abuseData);
            } catch (fallbackError) {
                console.error('All threat intelligence sources failed:', fallbackError);
                return this.getDefaultResponse(ip);
            }
        }
    }

    /**
     * Merge threat intelligence data from multiple sources
     * @param {Object} abuseData - Data from AbuseIPDB
     * @param {Object} vtData - Data from VirusTotal
     * @param {Object} otxData - Data from AlienVault OTX
     * @returns {Object} Merged threat intelligence
     */
    mergeThreatIntelData(abuseData, vtData, otxData) {
        // Start with base IP information (prefer abuseIPDB as primary source for ISP/location)
        const merged = {
            ip: abuseData.ip || vtData.ip || otxData.ip || '',

            // Geographic data - prefer abuseIPDB, then VT, then OTX
            city: abuseData.city || vtData.city || otxData.city || '',
            country: abuseData.country || vtData.country || otxData.country || '',
            countryCode: abuseData.countryCode || vtData.countryCode || otxData.countryCode || '',
            lat: abuseData.lat !== undefined ? abuseData.lat :
                   vtData.lat !== undefined ? vtData.lat :
                   otxData.lat !== undefined ? otxData.lat : 0,
            lng: abuseData.lng !== undefined ? abuseData.lng :
                   vtData.lng !== undefined ? vtData.lng :
                   otxData.lng !== undefined ? otxData.lng : 0,

            // Network/ISP data
            isp: abuseData.isp || vtData.asOwner || otxData.owner || '',
            asn: abuseData.asn || vtData.asn || otxData.asn || '',
            organization: abuseData.organization || vtData.asOwner || otxData.owner || '',

            // Threat intelligence scores (weighted average)
            abuseConfidence: this.calculateWeightedScore(
                abuseData.abuseConfidence,
                vtData.abuseConfidence,
                otxData.abuseConfidence,
                'abuseIPDB'
            ),
            threatScore: this.calculateWeightedScore(
                abuseData.threatScore,
                vtData.threatScore,
                otxData.threatScore
            ),

            // Combined malware tags (deduplicated)
            malwareTags: this.mergeUniqueArrays(
                abuseData.malwareTags || [],
                vtData.malwareTags || [],
                otxData.malwareTags || []
            ),

            // Combined botnet families (deduplicated)
            botnetFamilies: this.mergeUniqueArrays(
                abuseData.botnetFamilies || [],
                vtData.botnetFamilies || [],
                otxData.botnetFamilies || []
            ),

            // Most recent report date
            lastReported: this.getMostRecentDate([
                abuseData.lastReported,
                vtData.lastReported,
                otxData.lastReported
            ]),

            // Total reports (approximate - sum with deduplication consideration)
            totalReports: Math.min(
                (abuseData.totalReports || 0) +
                (vtData.totalReports || 0) +
                (otxData.totalReports || 0),
                10000 // Cap at reasonable maximum
            ),

            // ISP reputation (consensus or best available)
            ispReputation: this.getConsensusReputation([
                abuseData.ispReputation,
                vtData.ispReputation,
                otxData.ispReputation
            ]),

            // Threat description and recommendation (enhanced)
            threatDescription: this.generateThreatDescription(
                abuseData, vtData, otxData
            ),
            recommendedAction: this.generateRecommendedAction(
                abuseData, vtData, otxData
            ),

            // Additional source-specific data for detailed views
            sourceData: {
                abuseIPDB: abuseData,
                virusTotal: vtData,
                otx: otxData
            },

            // Metadata
            enrichmentTimestamp: new Date().toISOString(),
            sourcesUsed: this.getSourcesUsed(abuseData, vtData, otxData)
        };

        return merged;
    }

    /**
     * Calculate weighted score from multiple sources
     * @param {number} abuseScore - Score from AbuseIPDB
     * @param {number} vtScore - Score from VirusTotal
     * @param {number} otxScore - Score from OTX
     * @param {string} primarySource - Optional primary source for abuse confidence
     * @returns {number} Weighted score (0-100)
     */
    calculateWeightedScore(abuseScore, vtScore, otxScore, primarySource) {
        // Handle null/undefined values
        abuseScore = abuseScore !== null && abuseScore !== undefined ? abuseScore : 0;
        vtScore = vtScore !== null && vtScore !== undefined ? vtScore : 0;
        otxScore = otxScore !== null && otxScore !== undefined ? otxScore : 0;

        // For abuse confidence, AbuseIPDB is the primary source
        if (primarySource === 'abuseIPDB') {
            return abuseScore;
        }

        // Weighted average for threat score
        const weightedSum =
            (abuseScore * this.sourceWeights.abuseIPDB) +
            (vtScore * this.sourceWeights.virusTotal) +
            (otxScore * this.sourceWeights.otx);

        return Math.min(Math.round(weightedSum), 100);
    }

    /**
     * Merge multiple arrays, removing duplicates
     * @param {...Array} arrays - Arrays to merge
     * @returns {Array} Merged array with duplicates removed
     */
    mergeUniqueArrays(...arrays) {
        const merged = new Set();
        arrays.forEach(array => {
            if (Array.isArray(array)) {
                array.forEach(item => {
                    if (item !== null && item !== undefined && item !== '') {
                        merged.add(item.toString());
                    }
                });
            }
        });
        return Array.from(merged);
    }

    /**
     * Get the most recent date from an array of date strings
     * @param {Array} dates - Array of date strings (ISO format or null)
     * @returns {string|null} Most recent date or null
     */
    getMostRecentDate(dates) {
        const validDates = dates
            .filter(date => date !== null && date !== undefined && date !== '')
            .map(date => new Date(date))
            .filter(date => !isNaN(date.getTime()));

        if (validDates.length === 0) return null;

        const mostRecent = new Date(Math.max(...validDates.map(d => d.getTime())));
        return mostRecent.toISOString();
    }

    /**
     * Get consensus reputation from multiple sources
     * @param {Array} reputations - Array of reputation strings
     * @returns {string} Consensus reputation
     */
    getConsensusReputation(reputations) {
        // Filter out null/undefined/empty values
        const validReps = reputations
            .filter(rep => rep !== null && rep !== undefined && rep !== '')
            .map(rep => rep.toLowerCase().trim());

        if (validReps.length === 0) return 'unknown';

        // Count occurrences
        const counts = {};
        validReps.forEach(rep => {
            counts[rep] = (counts[rep] || 0) + 1;
        });

        // Return the most common reputation
        return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b);
    }

    /**
     * Generate enhanced threat description from all sources
     * @param {Object} abuseData - Data from AbuseIPDB
     * @param {Object} vtData - Data from VirusTotal
     * @param {Object} otxData - Data from OTX
     * @returns {string} Enhanced threat description
     */
    generateThreatDescription(abuseData, vtData, otxData) {
        const descriptions = [];

        if (abuseData.threatDescription) {
            descriptions.push(`AbuseIPDB: ${abuseData.threatDescription}`);
        }
        if (vtData.threatDescription) {
            descriptions.push(`VirusTotal: ${vtData.threatDescription}`);
        }
        if (otxData.threatDescription) {
            descriptions.push(`OTX: ${otxData.threatDescription}`);
        }

        // Add contextual information
        const contextBits = [];
        if (abuseData.totalReports && abuseData.totalReports > 100) {
            contextBits.push(`High abuse report count (${abuseData.totalReports})`);
        }
        if (vtData.maliciousVotes && vtData.maliciousVotes > 10) {
            contextBits.push(`Multiple AV detections (${vtData.maliciousVotes} engines)`);
        }
        if (otxData.pulseCount && otxData.pulseCount > 5) {
            contextBits.push(`Associated with ${otxData.pulseCount} threat pulses`);
        }

        // Combine descriptions
        let result = descriptions.join('; ');
        if (contextBits.length > 0) {
            result += ` - ${contextBits.join('; ')}`;
        }

        return result || 'No threat intelligence available';
    }

    /**
     * Generate recommended action based on threat intelligence
     * @param {Object} abuseData - Data from AbuseIPDB
     * @param {Object} vtData - Data from VirusTotal
     * @param {Object} otxData - Data from OTX
     * @returns {string} Recommended action
     */
    generateRecommendedAction(abuseData, vtData, otxData) {
        // Use the highest threat score to determine action level
        const threatScore = this.calculateWeightedScore(
            abuseData.threatScore,
            vtData.threatScore,
            otxData.threatScore
        );

        if (threatScore >= 80) {
            return 'BLOCK IMMEDIATELY - High confidence malicious IP from multiple threat intelligence sources';
        } else if (threatScore >= 60) {
            return 'BLOCK - Strong indicators of malicious activity from threat feeds';
        } else if (threatScore >= 30) {
            return 'MONITOR CLOSELY - Suspicious activity detected, investigate further';
        } else if (threatScore > 0) {
            return 'MONITOR - Minimal threat indicators, watch for changes in threat landscape';
        } else {
            return 'APPEARS CLEAN - No significant threat intelligence from integrated sources';
        }
    }

    /**
     * Get list of sources that successfully returned data
     * @param {Object} abuseData - Data from AbuseIPDB
     * @param {Object} vtData - Data from VirusTotal
     * @param {Object} otxData - Data from OTX
     * @returns {Array} Array of source names
     */
    getSourcesUsed(abuseData, vtData, otxData) {
        const sources = [];
        if (abuseData.abuseConfidence !== undefined && abuseData.abuseConfidence !== null) {
            sources.push('abuseIPDB');
        }
        if (vtData.threatScore !== undefined && vtData.threatScore !== null) {
            sources.push('virusTotal');
        }
        if (otxData.threatScore !== undefined && otxData.threatScore !== null) {
            sources.push('otx');
        }
        return sources;
    }

    /**
     * Get default enrichment when only one source works
     * @param {Object} primaryData - Data from primary working source
     * @returns {Object} Enriched data with defaults for missing fields
     */
    getDefaultEnrichment(primaryData) {
        return {
            ip: primaryData.ip || '',
            city: primaryData.city || '',
            country: primaryData.country || '',
            countryCode: primaryData.countryCode || '',
            lat: primaryData.lat || 0,
            lng: primaryData.lng || 0,
            isp: primaryData.isp || primaryData.asOwner || primaryData.owner || '',
            asn: primaryData.asn || '',
            organization: primaryData.organization || '',
            abuseConfidence: primaryData.abuseConfidence || 0,
            threatScore: primaryData.threatScore || 0,
            malwareTags: primaryData.malwareTags || [],
            botnetFamilies: primaryData.botnetFamilies || [],
            lastReported: primaryData.lastReported || null,
            totalReports: primaryData.totalReports || 0,
            ispReputation: primaryData.ispReputation || 'unknown',
            threatDescription: primaryData.threatDescription || 'Threat intelligence available from limited sources',
            recommendedAction: primaryData.recommendedAction || 'MONITOR - Limited threat intelligence available',
            sourceData: {
                abuseIPDB: primaryData.source === 'abuseIPDB' ? primaryData : {},
                virusTotal: primaryData.source === 'virusTotal' ? primaryData : {},
                otx: primaryData.source === 'otx' ? primaryData : {}
            },
            enrichmentTimestamp: new Date().toISOString(),
            sourcesUsed: [primaryData.source || 'unknown']
        };
    }

    /**
     * Get default response for invalid IP or complete failure
     * @param {string} ip - IP address
     * @returns {Object} Default response
     */
    getDefaultResponse(ip) {
        return {
            ip: ip,
            city: '',
            country: '',
            countryCode: '',
            lat: 0,
            lng: 0,
            isp: '',
            asn: '',
            organization: '',
            abuseConfidence: 0,
            threatScore: 0,
            malwareTags: [],
            botnetFamilies: [],
            lastReported: null,
            totalReports: 0,
            ispReputation: 'unknown',
            threatDescription: 'Invalid IP address or threat intelligence unavailable',
            recommendedAction: 'IGNORE - Unable to retrieve threat intelligence',
            sourceData: {
                abuseIPDB: {},
                virusTotal: {},
                otx: {}
            },
            enrichmentTimestamp: new Date().toISOString(),
            sourcesUsed: []
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
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThreatIntelManager;
} else {
    window.ThreatIntelManager = ThreatIntelManager;
}