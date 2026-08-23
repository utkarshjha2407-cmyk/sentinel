/**
 * SentinelMail AI - Map Visualizer
 * Interactive Leaflet-powered global mail relay hop mapping with dark-mode cyber aesthetic,
 * animated trajectory vectors, and origin radar pulses.
 */

class MapVisualizer {
    constructor(elementId = "geoMap") {
        this.elementId = elementId;
        this.map = null;
        this.markersGroup = null;
        this.linesGroup = null;
        this.initialized = false;
    }

    /**
     * Initialize Leaflet map with CartoDB DarkMatter tiles
     */
    init() {
        if (this.initialized || !document.getElementById(this.elementId)) return;

        // Default world center view
        this.map = L.map(this.elementId, {
            center: [25.0, 15.0],
            zoom: 2.5,
            minZoom: 1.5,
            maxZoom: 14,
            zoomControl: true,
            attributionControl: false
        });

        // Add Dark Matter Tile Layer
        L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            subdomains: "abcd",
            maxZoom: 19
        }).addTo(this.map);

        this.markersGroup = L.layerGroup().addTo(this.map);
        this.linesGroup = L.layerGroup().addTo(this.map);
        this.initialized = true;

        // Invalidate size on container resize
        window.addEventListener("resize", () => {
            if (this.map) this.map.invalidateSize();
        });
    }

    /**
     * Create Custom Pulse/Glow HTML Marker
     */
    createCustomIcon(label, type = "hop", isOrigin = false) {
        let className = "map-custom-node";
        if (isOrigin) className += " origin-pulse";
        if (type === "victim") className += " victim-node";

        const html = `
            <div class="${className}">
                <div class="node-ring"></div>
                <div class="node-core">${label}</div>
            </div>
        `;

        return L.divIcon({
            html: html,
            className: "leaflet-custom-marker-wrapper",
            iconSize: [36, 36],
            iconAnchor: [18, 18],
            popupAnchor: [0, -20]
        });
    }

    /**
     * Render Relay Chain Hops on the Map
     */
    renderHops(hops, originGeo) {
        this.init();
        if (!this.map) return;

        // Clear previous markers & polylines
        this.markersGroup.clearLayers();
        this.linesGroup.clearLayers();

        const latLngs = [];

        // 1. Plot Originating Server (Earliest public hop)
        if (originGeo && originGeo.lat && originGeo.lng) {
            const originCoord = [originGeo.lat, originGeo.lng];
            latLngs.push(originCoord);

            const isRisky = originGeo.threatScore > 50 || originGeo.tor || originGeo.vpn;
            const originIcon = this.createCustomIcon("📍", "origin", true);

            const popupContent = `
                <div class="map-popup-card">
                    <div class="map-popup-header ${isRisky ? 'risk-badge-crit' : 'risk-badge-safe'}">
                        ${isRisky ? '🚨 SUSPECT ORIGINATING NODE' : '✅ VERIFIED SENDER NODE'}
                    </div>
                    <div class="map-popup-body">
                        <p><strong>IP Address:</strong> <code>${originGeo.ip}</code></p>
                        <p><strong>Location:</strong> ${originGeo.city}, ${originGeo.country} (${originGeo.countryCode})</p>
                        <p><strong>Autonomous System:</strong> ${originGeo.asn}</p>
                        <p><strong>ISP / Host:</strong> ${originGeo.isp}</p>
                        <p><strong>Infrastructure:</strong> ${originGeo.tor ? 'TOR Exit Relay' : (originGeo.vpn ? 'VPN Gateway' : 'Standard Host')}</p>
                        <p><strong>Node Threat Index:</strong> <span class="threat-num">${originGeo.threatScore}/100</span></p>
                    </div>
                </div>
            `;

            const originMarker = L.marker(originCoord, { icon: originIcon }).bindPopup(popupContent);
            this.markersGroup.addLayer(originMarker);
        }

        // 2. Plot Intermediate Relay Hops
        hops.forEach((hop, idx) => {
            if (hop.geo && hop.geo.lat && hop.geo.lng) {
                const hopCoord = [hop.geo.lat, hop.geo.lng];
                
                // Avoid exact coordinate overlap by slight offset
                const offsetCoord = [hopCoord[0] + (idx * 0.02), hopCoord[1] + (idx * 0.02)];
                latLngs.push(offsetCoord);

                const hopIcon = this.createCustomIcon(`H${hop.hopNumber}`, "hop", false);
                const hopPopup = `
                    <div class="map-popup-card">
                        <div class="map-popup-header hop-badge">
                            🔄 RELAY HOP #${hop.hopNumber}
                        </div>
                        <div class="map-popup-body">
                            <p><strong>Relay IP:</strong> <code>${hop.ip}</code></p>
                            <p><strong>Server Location:</strong> ${hop.geo.city}, ${hop.geo.country}</p>
                            <p><strong>Mail Operator:</strong> ${hop.geo.isp}</p>
                            <p><strong>ASN:</strong> ${hop.geo.asn}</p>
                        </div>
                    </div>
                `;

                const marker = L.marker(offsetCoord, { icon: hopIcon }).bindPopup(hopPopup);
                this.markersGroup.addLayer(marker);
            }
        });

        // 3. Plot Destination (Victim Organization Endpoint)
        if (VICTIM_ORGANIZATION_ENDPOINT) {
            const victimCoord = [VICTIM_ORGANIZATION_ENDPOINT.lat, VICTIM_ORGANIZATION_ENDPOINT.lng];
            latLngs.push(victimCoord);

            const victimIcon = this.createCustomIcon("🎯", "victim", false);
            const victimPopup = `
                <div class="map-popup-card">
                    <div class="map-popup-header victim-badge">
                        🏢 TARGET INBOX (DESTINATION)
                    </div>
                    <div class="map-popup-body">
                        <p><strong>Facility:</strong> ${VICTIM_ORGANIZATION_ENDPOINT.isp}</p>
                        <p><strong>Destination:</strong> ${VICTIM_ORGANIZATION_ENDPOINT.city}, ${VICTIM_ORGANIZATION_ENDPOINT.country}</p>
                        <p><strong>Gateway ASN:</strong> ${VICTIM_ORGANIZATION_ENDPOINT.asn}</p>
                    </div>
                </div>
            `;

            const victimMarker = L.marker(victimCoord, { icon: victimIcon }).bindPopup(victimPopup);
            this.markersGroup.addLayer(victimMarker);
        }

        // 4. Draw Animated Polyline Connecting the Mail Relay Route
        if (latLngs.length > 1) {
            // Glow Polyline (outer)
            const glowLine = L.polyline(latLngs, {
                color: "#00f0ff",
                weight: 4,
                opacity: 0.35,
                dashArray: "8, 12",
                lineCap: "round"
            });
            this.linesGroup.addLayer(glowLine);

            // Core Line
            const coreLine = L.polyline(latLngs, {
                color: "#ff3366",
                weight: 2.5,
                opacity: 0.9,
                dashArray: "6, 8"
            });
            this.linesGroup.addLayer(coreLine);

            // Fit map to markers bounds
            const bounds = L.latLngBounds(latLngs);
            this.map.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
        }
    }

    /**
     * Refresh map rendering when tabs toggle
     */
    refresh() {
        if (this.map) {
            setTimeout(() => {
                this.map.invalidateSize();
            }, 200);
        }
    }
}

// Global Map Instance
window.mapVisualizer = new MapVisualizer();
