/**
 * SentinelMail AI - 3D Globe Visualizer
 * Immersive 3D Earth visualization for email threat attribution using Globe.gl
 */

class GlobeVisualizer {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            throw new Error(`Container element with ID ${containerId} not found`);
        }

        // Default options
        this.options = {
            backgroundImageUrl: 'https://cdn.jsdelivr.net/gh/harborhs/globe.gl/assets/world.jpg',
            bumpImageUrl: 'https://cdn.jsdelivr.net/gh/harborhs/globe.gl/assets/world-bump.png',
            cloudImageUrl: 'https://cdn.jsdelivr.net/gh/harborhs/globe.gl/assets/clouds-transparent.png',
            ...options
        };

        this.globeInstance = null;
        this.arcs = [];
        this.points = [];
        this.isInitialized = false;
        this.animationFrameId = null;

        // Threat level color scale
        this.threatColors = {
            low: '#4ade80',      // Green
            medium: '#fbbf24',   // Yellow
            high: '#f97316',     // Orange
            critical: '#dc2626'  // Red
        };

        this.init();
    }

    init() {
        // Create Globe.gl instance using the exposed Globe class from window
        this.globeInstance = new window.Globe(this.container)
            .globeImageUrl(this.options.backgroundImageUrl)
            .bumpImageUrl(this.options.bumpImageUrl)
            .showAtmosphere(true)
            .atmosphereColor('#3a86ff')
            .atmosphereAltitude(0.25)
            .polygonsTransitionDuration(800)
            .pointsTransitionDuration(800)
            .imageTransitionDuration(800)
            .labelsTransitionDuration(800)
            .arcsTransitionDuration(800)
            .arcsDashLength(0.4)
            .arcsDashGap(0.4)
            .arcsDashAnimateTime(1000)
            .onPointHover((item, event) => {
                this.handlePointHover(item, event);
            })
            .onPointClick((item, event) => {
                this.handlePointClick(item, event);
            });

        // Add mouse controls
        this.globeInstance.controls().enableZoom(true);
        this.globeInstance.controls().enableRotate(true);
        this.globeInstance.controls().enablePan(true);

        // Add ambient light for better visibility
        const THREE = window['THREE'];
        this.globeInstance.threeScene().add(new THREE.AmbientLight(0xffffff, 0.6));

        // Add directional light for sun effect
        const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
        directionalLight.position.set(5, 3, 5);
        this.globeInstance.threeScene().add(directionalLight);

        this.isInitialized = true;
        this.animate();
    }

    animate() {
        this.animationFrameId = requestAnimationFrame(() => this.animate());
        this.globeInstance.requestRedraw();
    }

    /**
     * Clear all visualizations
     */
    clear() {
        this.globeInstance.pointsData([]);
        this.globeInstance.arcsData([]);
        this.points = [];
        this.arcs = [];
    }

    /**
     * Set origin point (where email originated)
     * @param {Object} originData - Origin point data with lat, lng, threat info
     */
    setOriginPoint(originData) {
        if (!originData || !originData.lat || !originData.lng) return;

        const threatScore = originData.threatScore || 0;
        const color = this.getThreatColor(threatScore);
        const size = Math.max(0.8, Math.min(2.5, 0.8 + (threatScore / 100) * 1.7)); // Size 0.8-2.5 based on threat

        const pointData = {
            lat: originData.lat,
            lng: originData.lng,
            color,
            size: size * 25000, // Globe.gl scaling factor
            ...originData,
            // Additional data for tooltip/click handlers
            threatLevel: this.getThreatLevel(threatScore),
            threatDescription: originData.threatDescription || 'No threat intelligence available',
            recommendedAction: originData.recommendedAction || 'MONITOR',
            isOrigin: true
        };

        // Remove existing origin point if any
        this.points = this.points.filter(p => !p.isOrigin);
        this.points.push(pointData);

        this.globeInstance.pointsData(this.points);
    }

    /**
     * Set intermediate hops (relay points)
     * @param {Array} hopsData - Array of hop objects with lat, lng
     */
    setHopPoints(hopsData) {
        if (!Array.isArray(hopsData)) return;

        // Filter out invalid hops
        const validHops = hopsData.filter(hop =>
            hop.lat !== undefined && hop.lat !== null &&
            hop.lng !== undefined && hop.lng !== null
        );

        const hopPoints = validHops.map((hop, index) => ({
            lat: hop.lat,
            lng: hop.lng,
            color: '#60a5fa', // Blue for intermediate hops
            size: 15000,
            hopNumber: index + 1,
            ip: hop.ip || '',
            geo: hop.geo || {},
            isOrigin: false
        }));

        // Combine with existing points (keeping origin)
        const originPoints = this.points.filter(p => p.isOrigin);
        this.points = [...originPoints, ...hopPoints];
        this.globeInstance.pointsData(this.points);
    }

    /**
     * Set email routing arcs from origin to victim through hops
     * @param {Array} hopsData - Array of hop objects in order (origin -> ... -> victim)
     */
    setEmailArcs(hopsData) {
        if (!Array.isArray(hopsData) || hopsData.length < 2) return;

        const victimLocation = {
            lat: VICTIM_ORGANIZATION_ENDPOINT.lat,
            lng: VICTIM_ORGANIZATION_ENDPOINT.lng
        };

        // Create path: origin -> hop1 -> hop2 -> ... -> victim
        const path = [...hopsData, victimLocation];

        const arcsData = path.reduce((acc, point, index, arr) => {
            if (index < arr.length - 1) {
                const fromPoint = point;
                const toPoint = arr[index + 1];

                // Determine color based on threat level of origin or 'from' point
                const threatScore = fromPoint.threatScore || 0;
                const color = this.getThreatColor(threatScore);

                acc.push({
                    startLat: fromPoint.lat,
                    startLng: fromPoint.lng,
                    endLat: toPoint.lat,
                    endLng: toPoint.lng,
                    color,
                    ...(index === 0 && { // First arc from origin gets special styling
                        dashLength: 0.6,
                        dashGap: 0.3,
                        dashAnimateTime: 800
                    })
                });
            }
            return acc;
        }, []);

        this.arcs = arcsData;
        this.globeInstance.arcsData(this.arcs);
    }

    /**
     * Get color based on threat score (0-100)
     * @param {number} threatScore - Threat score from 0-100
     * @returns {string} Hex color code
     */
    getThreatColor(threatScore) {
        if (threatScore >= 75) return this.threatColors.critical;
        if (threatScore >= 50) return this.threatColors.high;
        if (threatScore >= 25) return this.threatColors.medium;
        return this.threatColors.low;
    }

    /**
     * Get threat level label based on score
     * @param {number} threatScore - Threat score from 0-100
     * @returns {string} Threat level label
     */
    getThreatLevel(threatScore) {
        if (threatScore >= 75) return 'CRITICAL';
        if (threatScore >= 50) return 'HIGH';
        if (threatScore >= 25) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Handle point hover event
     * @param {Object} item - Point data
     * @param {Event} event - Mouse event
     */
    handlePointHover(item, event) {
        // Could show tooltip here if needed
        // For now, we'll rely on click for detailed info
    }

    /**
     * Handle point click event
     * @param {Object} item - Point data
     * @param {Event} event - Mouse event
     */
    handlePointClick(item, event) {
        if (item.isOrigin) {
            // Show detailed threat intelligence panel for origin
            this.showThreatIntelPanel(item);
        }
        // Optionally could handle hop clicks too
    }

    /**
     * Show threat intelligence panel for clicked point
     * @param {Object} pointData - Point data for the clicked location
     */
    showThreatIntelPanel(pointData) {
        // Create or update threat intelligence panel
        let panel = document.getElementById('threat-intel-panel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'threat-intel-panel';
            panel.className = 'threat-intel-panel';
            document.body.appendChild(panel);
        }

        // Format the point data for display
        const threatScore = pointData.threatScore || 0;
        const threatLevel = this.getThreatLevel(threatScore);
        const color = this.getThreatColor(threatScore);

        panel.innerHTML = `
            <div class="threat-intel-header">
                <h3>Threat Intelligence Details</h3>
                <button class="close-panel" onclick="document.getElementById('threat-intel-panel').style.display='none'">&times;</button>
            </div>
            <div class="threat-intel-content">
                <div class="threat-score-badge" style="background-color: ${color}">
                    ${threatScore}<span>/${threatLevel}</span>
                </div>
                <div class="threat-details">
                    <p><strong>IP Address:</strong> ${pointData.ip || 'N/A'}</p>
                    <p><strong>Location:</strong> ${pointData.city || 'N/A'}, ${pointData.countryName || pointData.country || 'N/A'}</p>
                    <p><strong>ISP/Organization:</strong> ${pointData.isp || pointData.organization || pointData.asOwner || 'N/A'}</p>
                    <p><strong>ASN:</strong> ${pointData.asn || 'N/A'}</p>
                    <p><strong>Threat Description:</strong> ${pointData.threatDescription || 'No detailed threat intelligence available'}</p>
                    <p><strong>Recommended Action:</strong> ${pointData.recommendedAction || 'MONITOR'}</p>
                    ${pointData.malwareTags && pointData.malwareTags.length > 0 ? `
                        <div class="threat-tags">
                            <strong>Malware Indicators:</strong>
                            <span class="tags">${pointData.malwareTags.map(tag => `<span class="tag">${tag}</span>`).join('')}</span>
                        </div>
                    ` : ''}
                    ${pointData.botnetFamilies && pointData.botnetFamilies.length > 0 ? `
                        <div class="threat-tags">
                            <strong>Botnet Associations:</strong>
                            <span class="tags">${pointData.botnetFamilies.map(family => `<span class="tag">${family}</span>`).join('')}</span>
                        </div>
                    ` : ''}
                    ${pointData.lastReported ? `
                        <p><strong>Last Reported:</strong> ${new Date(pointData.lastReported).toLocaleString()}</p>
                    ` : ''}
                    ${pointData.totalReports !== undefined ? `
                        <p><strong>Total Abuse Reports:</strong> ${pointData.totalReports}</p>
                    ` : ''}
                </div>
            </div>
        `;

        // Position panel near the clicked point (simplified - in production would use proper positioning)
        panel.style.display = 'block';
        panel.style.top = '50%';
        panel.style.left = '50%';
        panel.style.transform = 'translate(-50%, -50%)';
    }

    /**
     * Set victim/target location (fixed for demo)
     */
    setVictimPoint() {
        const victimPoint = {
            lat: VICTIM_ORGANIZATION_ENDPOINT.lat,
            lng: VICTIM_ORGANIZATION_ENDPOINT.lng,
            color: '#ef4444', // Red for victim
            size: 20000,
            label: VICTIM_ORGANIZATION_ENDPOINT.city,
            country: VICTIM_ORGANIZATION_ENDPOINT.country,
            isVictim: true
        };

        // Add victim point to existing points
        const nonVictimPoints = this.points.filter(p => !p.isVictim);
        this.points = [...nonVictimPoints, victimPoint];
        this.globeInstance.pointsData(this.points);
    }

    /**
     * Destroy visualizer and clean up resources
     */
    destroy() {
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
        }
        if (this.globeInstance) {
            this.globeInstance.destroy();
        }
        this.isInitialized = false;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GlobeVisualizer;
} else {
    window.GlobeVisualizer = GlobeVisualizer;
}