/**
 * SentinelMail AI - Application Controller
 * UI Interaction, Scan Lifecycle, Canvas Attribution Graph, Case Manager, and Report Generator.
 */

class AppController {
    constructor() {
        this.currentScan = null;
        this.cases = JSON.parse(localStorage.getItem("sentinel_mail_cases") || "[]");
    }

    init() {
        this.bindEvents();
        this.loadDefaultSample("sbi_phishing");
        this.renderSavedCases();
        this.initGraphCanvas();
        this.initGlobeVisualizer();
    }

    bindEvents() {
        // Navigation Tabs
        document.querySelectorAll(".nav-link").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const targetTab = e.currentTarget.getAttribute("data-tab");
                this.switchTab(targetTab);
            });
        });

        // Sample Presets
        document.querySelectorAll(".preset-card").forEach(card => {
            card.addEventListener("click", (e) => {
                const sampleId = e.currentTarget.getAttribute("data-sample");
                this.loadDefaultSample(sampleId);
            });
        });

        // Run Analysis Button
        const analyzeBtn = document.getElementById("analyzeBtn");
        if (analyzeBtn) {
            analyzeBtn.addEventListener("click", () => this.runAnalysis());
        }

        // Clear Input
        const clearBtn = document.getElementById("clearInputBtn");
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                document.getElementById("rawEmailInput").value = "";
                document.getElementById("inputCharCount").innerText = "0 chars";
            });
        }

        // File Upload / Dropzone
        const fileInput = document.getElementById("emlFileInput");
        const dropZone = document.getElementById("emailDropZone");

        if (fileInput) {
            fileInput.addEventListener("change", (e) => this.handleFileUpload(e.target.files[0]));
        }

        if (dropZone) {
            dropZone.addEventListener("dragover", (e) => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
            dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
            dropZone.addEventListener("drop", (e) => {
                e.preventDefault();
                dropZone.classList.remove("dragover");
                if (e.dataTransfer.files.length > 0) {
                    this.handleFileUpload(e.dataTransfer.files[0]);
                }
            });
        }

        // Character count listener
        const rawInput = document.getElementById("rawEmailInput");
        if (rawInput) {
            rawInput.addEventListener("input", (e) => {
                const count = e.target.value.length;
                document.getElementById("inputCharCount").innerText = `${count.toLocaleString()} chars`;
            });
        }

        // Sub-tabs in Analyzer Results
        document.querySelectorAll(".result-tab-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const panel = e.currentTarget.getAttribute("data-panel");
                document.querySelectorAll(".result-tab-btn").forEach(b => b.classList.remove("active"));
                document.querySelectorAll(".result-panel").forEach(p => p.classList.remove("active"));

                e.currentTarget.classList.add("active");
                const targetPanel = document.getElementById(panel);
                if (targetPanel) targetPanel.classList.add("active");

                if (panel === "panel-geo") {
                    window.mapVisualizer.refresh();
                } else if (panel === "panel-graph") {
                    this.drawAttributionGraph();
                }
            });
        });

        // Case Management Actions
        const saveCaseBtn = document.getElementById("saveCaseBtn");
        if (saveCaseBtn) {
            saveCaseBtn.addEventListener("click", () => this.saveCurrentToCase());
        }

        // Report & Export Actions
        const copyHashBtn = document.getElementById("copyHashBtn");
        if (copyHashBtn) {
            copyHashBtn.addEventListener("click", () => this.copyEvidenceHash());
        }
    }

    switchTab(tabId) {
        document.querySelectorAll(".nav-link").forEach(btn => btn.classList.remove("active"));
        document.querySelectorAll(".view-section").forEach(sec => sec.classList.remove("active"));

        const targetBtn = document.querySelector(`.nav-link[data-tab="${tabId}"]`);
        const targetSec = document.getElementById(tabId);

       if (targetBtn) targetBtn.classList.add("active");
       if (targetSec) targetSec.classList.add("active");

       if (tabId === "view-geo") {
            if (window.globeVisualizer && window.globeVisualizer.globeInstance) {
                window.globeVisualizer.globeInstance.requestRedraw();
            }
       } else if (tabId === "view-graph") {
           this.drawAttributionGraph();
       }
   }

    loadDefaultSample(sampleKey) {
        const sample = SAMPLE_EMAILS[sampleKey];
        if (!sample) return;

        const input = document.getElementById("rawEmailInput");
        if (input) {
            input.value = sample.raw;
            document.getElementById("inputCharCount").innerText = `${sample.raw.length.toLocaleString()} chars`;
        }

        document.querySelectorAll(".preset-card").forEach(c => c.classList.remove("active"));
        const activeCard = document.querySelector(`.preset-card[data-sample="${sampleKey}"]`);
        if (activeCard) activeCard.classList.add("active");

        // Automatically execute scan for smooth hackathon demo
        this.runAnalysis();
    }

    handleFileUpload(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            const input = document.getElementById("rawEmailInput");
            if (input) {
                input.value = content;
                document.getElementById("inputCharCount").innerText = `${content.length.toLocaleString()} chars`;
            }
            this.runAnalysis();
        };
        reader.readAsText(file);
    }

    async runAnalysis() {
        const raw = document.getElementById("rawEmailInput").value.trim();
        if (!raw) {
            alert("Please paste raw email headers/body or select a sample preset.");
            return;
        }

        const statusContainer = document.getElementById("btnScanStatus");
        const statusText = document.getElementById("btnScanStatusText");
        const analyzeBtn = document.getElementById("analyzeBtn");

        if (statusContainer) statusContainer.style.display = "inline-flex";
        if (analyzeBtn) {
            analyzeBtn.disabled = true;
            analyzeBtn.style.opacity = "0.7";
        }

        const steps = [
            "Parsing RFC headers...",
            "Checking SPF/DKIM/DMARC...",
            "Running NLP AI models...",
            "Tracing GeoIP path..."
        ];

        for (const step of steps) {
            if (statusText) statusText.innerText = step;
            await new Promise(r => setTimeout(r, 200));
        }

        try {
            const result = await window.forensicEngine.executeForensicScan(raw);
            this.currentScan = result;
            this.renderScanResults(result);
        } catch (err) {
            console.error("Forensic scan error:", err);
            alert("Failed to parse email: " + err.message);
        } finally {
            if (statusContainer) statusContainer.style.display = "none";
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                analyzeBtn.style.opacity = "1";
            }
        }
    }

    renderScanResults(res) {
        const resultsContainer = document.getElementById("resultsContainer");
        if (resultsContainer) resultsContainer.style.display = "block";

        // 1. Overall Threat Banner & Score
        const scoreVal = document.getElementById("scoreValue");
        const verdictBadge = document.getElementById("threatVerdictBadge");
        const categoryText = document.getElementById("threatCategoryText");
        const scoreArc = document.getElementById("scoreGaugeArc");

        if (scoreVal) scoreVal.innerText = res.threatSummary.score;
        if (verdictBadge) {
            verdictBadge.innerText = res.threatSummary.verdict;
            verdictBadge.className = `verdict-badge verdict-${res.threatSummary.verdict.toLowerCase()}`;
        }
        if (categoryText) categoryText.innerText = res.threatSummary.category;

        // Remove any existing email type badges to prevent duplicates
        const existingBadges = document.querySelectorAll('.email-type-badge');
        existingBadges.forEach(badge => badge.remove());

        // Create the email type badge
        const emailTypeBadge = document.createElement('span');
        emailTypeBadge.className = `verdict-badge email-type-badge email-type-${res.threatSummary.emailType.toLowerCase()}`;
        emailTypeBadge.innerText = res.threatSummary.emailType;
        if (categoryText) {
            categoryText.parentNode.insertBefore(emailTypeBadge, categoryText.nextSibling);
        }

        if (scoreArc) {
            // Gauge animation (circumference is ~283 for r=45)
            const offset = 283 - (283 * res.threatSummary.score) / 100;
            scoreArc.style.strokeDashoffset = offset;
            scoreArc.style.stroke = res.threatSummary.threatColor;
        }

        // Threat Factors List
        const factorsContainer = document.getElementById("threatFactorsList");
        if (factorsContainer) {
            factorsContainer.innerHTML = res.threatSummary.threatFactors.length > 0 
                ? res.threatSummary.threatFactors.map(f => `<span class="factor-chip">⚠️ ${f}</span>`).join("")
                : `<span class="factor-chip chip-clean">✅ No high-risk threats detected</span>`;
        }

        // 2. Parsed Key Headers Table
        document.getElementById("valFrom").innerText = `${res.auth.from.name ? res.auth.from.name + ' ' : ''}<${res.auth.from.email || 'None'}>`;
        document.getElementById("valReturnPath").innerText = `<${res.auth.returnPath.email || 'None'}>`;
        document.getElementById("valReplyTo").innerText = res.auth.replyTo.email ? `<${res.auth.replyTo.email}>` : "Same as sender";
        document.getElementById("valTo").innerText = res.parsed.headers["to"] || "Undisclosed-recipients";
        document.getElementById("valSubject").innerText = res.parsed.headers["subject"] || "(No Subject)";
        document.getElementById("valDate").innerText = res.parsed.headers["date"] || "Unknown Date";
        document.getElementById("valMsgId").innerText = res.parsed.headers["message-id"] || "None";

        // 3. Protocol & Authentication Status Badges
        this.renderAuthCard("authSpf", res.auth.spf.status, res.auth.spf.details);
        this.renderAuthCard("authDkim", res.auth.dkim.status, `Selector: ${res.auth.dkim.selector}`);
        this.renderAuthCard("authDmarc", res.auth.dmarc.status, `Policy: ${res.auth.dmarc.policy}`);

        // Anomalies List
        const anomalyBox = document.getElementById("anomaliesBox");
        if (anomalyBox) {
            if (res.auth.anomalies.length > 0) {
                anomalyBox.innerHTML = res.auth.anomalies.map(a => `
                    <div class="anomaly-alert-card severity-${a.severity.toLowerCase()}">
                        <div class="anomaly-title">🚨 ${a.type} [${a.severity}]</div>
                        <div class="anomaly-desc">${a.detail}</div>
                    </div>
                `).join("");
            } else {
                anomalyBox.innerHTML = `<div class="anomaly-clean">✅ Sender domain alignment and Message-ID match standard authorized routing.</div>`;
            }
        }

        // 4. NLP Content Analysis
        document.getElementById("nlpUrgencyVal").innerText = `${res.nlp.urgencyScore}%`;
        document.getElementById("nlpFinancialVal").innerText = `${res.nlp.financialScore}%`;
        document.getElementById("nlpCredentialVal").innerText = `${res.nlp.credentialScore}%`;

        document.getElementById("nlpUrgencyBar").style.width = `${res.nlp.urgencyScore}%`;
        document.getElementById("nlpFinancialBar").style.width = `${res.nlp.financialScore}%`;
        document.getElementById("nlpCredentialBar").style.width = `${res.nlp.credentialScore}%`;

        const nlpBadges = document.getElementById("nlpDetectedKeywords");
        if (nlpBadges) {
            const allCues = [...res.nlp.matchedUrgency, ...res.nlp.matchedFinancial, ...res.nlp.matchedCredentials];
            nlpBadges.innerHTML = allCues.length > 0 
                ? allCues.map(c => `<span class="nlp-cue-tag">"${c}"</span>`).join(" ")
                : `<span style="color: var(--text-muted);">None detected</span>`;
        }

        // Malicious URL Table
        const urlTable = document.getElementById("urlAnalysisTableBody");
        if (urlTable) {
            if (res.nlp.extractedUrls.length > 0) {
                urlTable.innerHTML = res.nlp.extractedUrls.map(u => `
                    <tr>
                        <td><code class="url-snippet">${this.escapeHtml(u.url)}</code></td>
                        <td><span class="url-risk-badge badge-${u.risk.toLowerCase()}">${u.risk}</span></td>
                        <td>${u.reason}</td>
                    </tr>
                `).join("");
            } else {
                urlTable.innerHTML = `<tr><td colspan="3" style="text-align:center; color: var(--text-muted);">No hyperlinked URLs found in email body.</td></tr>`;
            }
        }

        // 5. Origin GeoLocation & Relay Hop Table
        const originInfoBox = document.getElementById("originNodeSummary");
        if (originInfoBox && res.originGeo) {
            originInfoBox.innerHTML = `
                <div class="origin-grid">
                    <div class="origin-item">
                        <span class="lbl">Originating IP:</span>
                        <span class="val"><code>${res.originGeo.ip}</code></span>
                    </div>
                    <div class="origin-item">
                        <span class="lbl">Location:</span>
                        <span class="val">📍 ${res.originGeo.city}, ${res.originGeo.country} (${res.originGeo.countryCode})</span>
                    </div>
                    <div class="origin-item">
                        <span class="lbl">Operator / ISP:</span>
                        <span class="val">${res.originGeo.isp}</span>
                    </div>
                    <div class="origin-item">
                        <span class="lbl">Autonomous System:</span>
                        <span class="val">${res.originGeo.asn}</span>
                    </div>
                    <div class="origin-item">
                        <span class="lbl">Anonymity Gateway:</span>
                        <span class="val">${res.originGeo.tor ? '🔴 Active TOR Exit Relay' : (res.originGeo.vpn ? '🟠 Commercial VPN Gateway' : '🟢 Direct Non-Proxy Host')}</span>
                    </div>
                </div>
            `;
        }

        const hopTableBody = document.getElementById("relayHopTableBody");
        if (hopTableBody) {
            if (res.hops.length > 0) {
                hopTableBody.innerHTML = res.hops.map(h => `
                    <tr>
                        <td><span class="hop-num">#${h.hopNumber}</span></td>
                        <td><code>${h.ip}</code></td>
                        <td>${h.geo.city}, ${h.geo.country}</td>
                        <td>${h.geo.isp}</td>
                        <td>${h.geo.asn}</td>
                        <td>${h.geo.tor ? '🧅 TOR' : (h.geo.vpn ? '🛡️ VPN' : (h.geo.proxy ? '⚡ Proxy' : '🖥️ Standard'))}</td>
                    </tr>
                `).join("");
            } else {
                hopTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No external IPv4 relay hops identified in Received headers.</td></tr>`;
            }
        }

        // 6. Update 3D Globe Visualization
        if (window.globeVisualizer) {
            // Set origin point with threat intelligence
            if (res.originGeo) {
                window.globeVisualizer.setOriginPoint(res.originGeo);
            }

            // Set intermediate hop points
            if (res.hops && res.hops.length > 0) {
                window.globeVisualizer.setHopPoints(res.hops);

                // Set email routing arcs (origin -> hops -> victim)
                window.globeVisualizer.setEmailArcs(res.hops);

                // Set victim point
                window.globeVisualizer.setVictimPoint();
            }

            // Refresh globe visualization
            window.globeVisualizer.globeInstance.requestRedraw();
        }

        // 6.5. Update 2D Map Visualization
        if (window.mapVisualizer) {
            // Set origin point and hops
            if (res.originGeo) {
                window.mapVisualizer.renderHops(res.hops || [], res.originGeo);
            }
        }

        // 7. Render Attribution Graph
        this.drawAttributionGraph();

        // 8. Digital Evidence Hashes
        document.getElementById("valSha256").innerText = res.hashes.sha256;
        document.getElementById("valMd5").innerText = res.hashes.md5;
        document.getElementById("valPayloadSize").innerText = `${res.hashes.payloadLength.toLocaleString()} bytes`;
        document.getElementById("valTimestamp").innerText = res.hashes.timestamp;
    }

    renderAuthCard(cardId, status, details) {
        const el = document.getElementById(cardId);
        if (!el) return;

        const statLower = status.toLowerCase();
        let badgeClass = "badge-pass";
        let icon = "✅";

        if (statLower.includes("fail")) {
            badgeClass = "badge-fail";
            icon = "❌";
        } else if (statLower.includes("softfail") || statLower.includes("neutral")) {
            badgeClass = "badge-warn";
            icon = "⚠️";
        } else if (statLower.includes("none")) {
            badgeClass = "badge-none";
            icon = "⚪";
        }

        el.innerHTML = `
            <div class="auth-header">
                <span class="auth-name">${cardId.replace("auth", "").toUpperCase()}</span>
                <span class="auth-status-badge ${badgeClass}">${icon} ${status}</span>
            </div>
            <div class="auth-detail">${details}</div>
        `;
    }

    initGraphCanvas() {
        this.canvas = document.getElementById("attributionCanvas");
        if (this.canvas) {
            this.ctx = this.canvas.getContext("2d");
            this.resizeCanvas();
            window.addEventListener("resize", () => {
                this.resizeCanvas();
                this.drawAttributionGraph();
            });
        }
    }

    initGlobeVisualizer() {
        console.log('Initializing globe visualizer...');

        // Check if THREE.js is loaded
        if (!window.THREE) {
            console.error('THREE.js not loaded');
            this.showGlobeError('Three.js library is required for 3D globe visualization. Please check your network connection and try again.');
            return;
        }

        // Wait for Globe class to be available on window.Globe (the standard export GlobeVisualizer expects)
        const waitForGlobe = () => {
            return new Promise((resolve, reject) => {
                const timeout = 20000; // Increased to 20 second timeout for reliability
                const startTime = Date.now();

                const checkForGlobe = () => {
                    let GlobeClass = null;
                    let source = '';

                    // Primary check: window.Globe (what GlobeVisualizer expects)
                    if (window.Globe && typeof window.Globe === 'function') {
                        GlobeClass = window.Globe;
                        source = 'window.Globe';
                    }
                    // Secondary check: window.globe.Globe (common alternative)
                    else if (window.globe && typeof window.globe === 'object' && window.globe.Globe && typeof window.globe.Globe === 'function') {
                        GlobeClass = window.globe.Globe;
                        source = 'window.globe.Globe';
                        // Ensure it's also available where GlobeVisualizer expects it
                        window.Globe = GlobeClass;
                    }
                    // Tertiary check: window.globe as direct function (less common but possible)
                    else if (window.globe && typeof window.globe === 'function') {
                        GlobeClass = window.globe;
                        source = 'window.globe (direct function)';
                        window.Globe = GlobeClass;
                    }
                    // Quaternary check: ES6 module default export
                    else if (window.globe && window.globe.default && typeof window.globe.default === 'function') {
                        GlobeClass = window.globe.default;
                        source = 'window.globe.default';
                        window.Globe = GlobeClass;
                    }

                    if (GlobeClass) {
                        console.log(`Globe class found and assigned to window.Globe from ${source}`);
                        resolve(GlobeClass);
                        return;
                    }

                    // Check if we've timed out
                    if (Date.now() - startTime > timeout) {
                        // Diagnostic logging
                        console.log('Globe class not found on window.Globe after timeout. Diagnostics:');
                        console.log('  window.THREE:', !!window.THREE, typeof window.THREE);
                        console.log('  window.globe:', !!window.globe, typeof window.globe);
                        if (window.globe) {
                            console.log('  window.globe properties:', Object.keys(window.globe));
                        }
                        console.log('  window.Globe:', !!window.Globe, typeof window.Globe);

                        // Check for any globe-related globals
                        const globeKeys = Object.keys(window).filter(k => k.toLowerCase().includes('globe'));
                        if (globeKeys.length > 0) {
                            console.log('  Globe-related window properties:');
                            globeKeys.forEach(key => {
                                console.log(`    window.${key}:`, typeof window[key]);
                                if (window[key] && typeof window[key] === 'object') {
                                    console.log(`      Properties:`, Object.keys(window[key]));
                                }
                            });
                        } else {
                            console.log('  No globe-related properties found on window');
                        }

                        reject(new Error(`Globe class not available on window.Globe after ${timeout/1000} seconds`));
                        return;
                    }

                    // Try again in 200ms (longer interval to reduce CPU usage)
                    setTimeout(checkForGlobe, 200);
                };

                checkForGlobe();
            });
        };

        // Wait for Globe and then initialize
        waitForGlobe()
            .then(GlobeClass => {
                console.log('Globe class ready for use:', GlobeClass);

                // Try to create a simple globe instance first to test if it works
                try {
                    console.log('Testing Globe instantiation...');
                    const testContainer = document.createElement('div');
                    testContainer.style.width = '100px';
                    testContainer.style.height = '100px';
                    testContainer.style.display = 'none'; // Don't affect layout
                    document.body.appendChild(testContainer);

                    const testGlobe = new GlobeClass(testContainer);
                    console.log('Globe instantiation test successful:', testGlobe);

                    // Clean up test container
                    document.body.removeChild(testContainer);
                } catch (testError) {
                    console.error('Globe instantiation test failed:', testError);
                    this.showGlobeError('The Globe class cannot be instantiated properly. This may be due to missing dependencies, incompatible globe.gl/three.js versions, or browser WebGL support issues.');
                    return;
                }

                // Now try to initialize our GlobeVisualizer
                if (!window.GlobeVisualizer) {
                    console.error('GlobeVisualizer class not found');
                    this.showGlobeError('GlobeVisualizer component failed to load. Check console for details.');
                    return;
                }

                // All dependencies are available, try to initialize
                try {
                    console.log('Creating GlobeVisualizer instance...');
                    window.globeVisualizer = new window.GlobeVisualizer("globeContainer");
                    console.log('Globe visualizer initialized successfully');
                    console.log('globeInstance:', window.globeVisualizer.globeInstance);

                    // Verify the globe instance is working
                    if (!window.globeVisualizer.globeInstance) {
                        throw new Error('Globe instance was not created properly');
                    }

                    // Force an initial redraw to ensure it displays content
                    setTimeout(() => {
                        if (window.globeVisualizer && window.globeVisualizer.globeInstance) {
                            window.globeVisualizer.globeInstance.requestRedraw();
                            console.log('Initial globe redraw scheduled');
                        }
                    }, 300);

                } catch (error) {
                    console.error('Error initializing globe visualizer:', error);
                    console.error('Error stack:', error.stack);

                    this.showGlobeError(`Globe visualization failed to initialize: ${error.message}`);

                    // Try to recoverGlobeVisualization();
                }
            })
            .catch(error => {
                console.error('Failed to get Globe class:', error);
                this.showGlobeError('Globe.gl library did not load properly or expose the Globe class. Please try refreshing the page.');

                // Still attempt recovery in case it's a transient issue
                recoverGlobeVisualization();
            });

        // Helper function to attempt recovery
        function recoverGlobeVisualization() {
            console.log('Attempting to recover globe visualization...');
            setTimeout(() => {
                try {
                    if (window.GlobeVisualizer) {
                        window.globeVisualizer = new window.GlobeVisualizer("globeContainer");
                        console.log('Globe visualizer recovered successfully');

                        // Clear error state and show container
                        const globeContainer = document.getElementById("globeContainer");
                        if (globeContainer) {
                            globeContainer.innerHTML = '';
                            globeContainer.style.display = 'block';

                            // Trigger redraw
                            setTimeout(() => {
                                if (window.globeVisualizer && window.globeVisualizer.globeInstance) {
                                    window.globeVisualizer.globeInstance.requestRedraw();
                                }
                            }, 300);
                        }
                    }
                } catch (recoveryError) {
                    console.error('Globe visualization recovery failed:', recoveryError);
                    // Keep any existing error message visible
                }
            }, 4000); // Try recovery after 4 seconds
        }
    }

    showGlobeError(message) {
        const globeContainer = document.getElementById("globeContainer");
        if (globeContainer) {
            globeContainer.innerHTML = `<div style="padding: 20px; text-align: center; color: #ff6b6b;">
                <h3>Globe Visualization Error</h3>
                <p>${message}</p>
                <div style="margin-top: 15px; font-size: 0.9rem; color: #ccc;">
                    <p>Please try:</p>
                    <ul style="text-align: left;">
                        <li>Refreshing the page (Ctrl+F5 or Cmd+Shift+R)</li>
                        <li>Checking browser console for detailed error information</li>
                        <li>Ensuring WebGL is enabled in your browser settings</li>
                        <li>Trying a different browser (Chrome, Firefox, Safari, Edge)</li>
                    </ul>
                </div>
            </div>`;
        }
    }

    resizeCanvas() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width || 800;
        this.canvas.height = 360;
    }

    drawAttributionGraph() {
        if (!this.canvas || !this.ctx || !this.currentScan) return;
        const graph = this.currentScan.attributionGraph;
        const ctx = this.ctx;
        const width = this.canvas.width;
        const height = this.canvas.height;

        ctx.clearRect(0, 0, width, height);

        // Calculate Node Positions in an arc / chain layout
        const nodes = graph.nodes;
        const count = nodes.length;
        const stepX = (width - 160) / (count - 1 || 1);

        nodes.forEach((node, i) => {
            node.x = 80 + i * stepX;
            // Alternating wave height for visual appeal
            node.y = (height / 2) + (i % 2 === 0 ? -30 : 30);
        });

        // 1. Draw Links
        graph.links.forEach(link => {
            const src = nodes.find(n => n.id === link.source);
            const tgt = nodes.find(n => n.id === link.target);

            if (src && tgt) {
                // Bezier Curve
                ctx.beginPath();
                ctx.moveTo(src.x, src.y);
                const cpX = (src.x + tgt.x) / 2;
                const cpY = (src.y + tgt.y) / 2 - 25;
                ctx.quadraticCurveTo(cpX, cpY, tgt.x, tgt.y);
                ctx.strokeStyle = "rgba(0, 240, 255, 0.4)";
                ctx.lineWidth = 2;
                ctx.setLineDash([5, 5]);
                ctx.stroke();
                ctx.setLineDash([]);

                // Link Label
                ctx.font = "11px Inter, sans-serif";
                ctx.fillStyle = "#94a3b8";
                ctx.textAlign = "center";
                ctx.fillText(link.label, cpX, cpY - 8);
            }
        });

        // 2. Draw Nodes
        nodes.forEach(node => {
            // Glow
            ctx.shadowBlur = 15;
            ctx.shadowColor = node.type === "attacker" || node.type === "spoof" ? "#ff3366" : "#00f0ff";

            // Circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);
            ctx.fillStyle = node.type === "attacker" || node.type === "spoof" ? "#1f0f18" : "#0c1b2c";
            ctx.fill();
            ctx.strokeStyle = node.type === "attacker" || node.type === "spoof" ? "#ff3366" : (node.type === "victim" ? "#00ff88" : "#00f0ff");
            ctx.lineWidth = 2.5;
            ctx.stroke();

            ctx.shadowBlur = 0;

            // Icon
            ctx.font = "16px sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(node.icon, node.x, node.y);

            // Text Labels
            ctx.font = "bold 12px Inter, sans-serif";
            ctx.fillStyle = "#ffffff";
            ctx.fillText(node.label, node.x, node.y + 36);

            ctx.font = "10px Inter, sans-serif";
            ctx.fillStyle = "#94a3b8";
            ctx.fillText(node.sub, node.x, node.y + 50);
        });
    }

    saveCurrentToCase() {
        if (!this.currentScan) {
            alert("No active scan to save. Run an email analysis first.");
            return;
        }

        // Extract features for campaign intelligence
        const subject = this.currentScan.parsed.headers["subject"] || "";
        const body = this.currentScan.parsed.body || "";
        const senderDomain = this.currentScan.auth.from.domain || "";
        const originASN = this.currentScan.originGeo ? this.currentScan.originGeo.asn : "";
        const threatCategory = this.currentScan.threatSummary.category;
        const threatVerdict = this.currentScan.threatSummary.verdict;

        // Extract keywords for similarity matching
        const subjectKeywords = window.forensicEngine.extractKeywords(subject);

        const newCase = {
            id: `CASE-SIH-${Date.now().toString().slice(-6)}`,
            subject: subject || "No Subject",
            sender: this.currentScan.auth.from.email || "Unknown Sender",
            verdict: threatVerdict,
            score: this.currentScan.threatSummary.score,
            origin: this.currentScan.originGeo ? `${this.currentScan.originGeo.city}, ${this.currentScan.originGeo.country}` : "Unknown",
            originASN: originASN,
            senderDomain: senderDomain,
            threatCategory: threatCategory,
            subjectKeywords: Array.from(subjectKeywords), // Convert Set to Array for storage
            timestamp: new Date().toLocaleString(),
            raw: this.currentScan.parsed.rawText
        };

        this.cases.unshift(newCase);
        localStorage.setItem("sentinel_mail_cases", JSON.stringify(this.cases));
        this.renderSavedCases();
        alert(`Case #${newCase.id} successfully recorded in active forensic incident logs.`);
    }

    renderSavedCases() {
        const container = document.getElementById("casesTableBody");
        if (!container) return;

        // Check if grouped view is enabled
        const groupedView = document.getElementById("campaignToggle") ?
                          document.getElementById("campaignToggle").checked : false;

        if (this.cases.length === 0) {
            container.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted);">No active forensic cases logged yet. Click "Save to Incident File" on any scan.</td></tr>`;
            return;
        }

        if (groupedView) {
            // Group cases by campaign
            this.renderGroupedCases(container);
        } else {
            // Original flat view
            container.innerHTML = this.cases.map((c, i) => `
                <tr>
                    <td><code>${c.id}</code></td>
                    <td>${c.timestamp}</td>
                    <td><strong>${this.escapeHtml(c.subject)}</strong></td>
                    <td><code>${this.escapeHtml(c.sender)}</code></td>
                    <td>📍 ${c.origin}</td>
                    <td><span class="verdict-badge verdict-${c.verdict.toLowerCase()}">${c.verdict} (${c.score}/100)</span></td>
                    <td>
                        <button class="btn-xs btn-inspect" onclick="window.appController.loadCaseByIndex(${i})">Inspect</button>
                        <button class="btn-xs btn-delete" onclick="window.appController.deleteCaseByIndex(${i})">Delete</button>
                    </td>
                </tr>
            `).join("");
        }
    }

    /**
     * Group cases by campaign similarity and render grouped view
     */
    renderGroupedCases(container) {
        if (this.cases.length === 0) {
            container.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted);">No active forensic cases logged yet. Click "Save to Incident File" on any scan.</td></tr>`;
            return;
        }

        // Group cases using similarity threshold
        const campaigns = this.groupCasesIntoCampaigns(this.cases, 0.6); // 60% similarity threshold

        let html = '';
        campaigns.forEach((campaign, campaignIndex) => {
            if (campaign.length === 0) return;

            // Calculate campaign metadata
            const timestamps = campaign.map(c => new Date(c.timestamp));
            const earliest = new Math.min(...timestamps.map(t => t.getTime()));
            const latest = new Math.max(...timestamps.map(t => t.getTime()));

            // Find common traits
            const senderDomains = [...new Set(campaign.map(c => c.senderDomain))];
            const originASNs = [...new Set(campaign.map(c => c.originASN))];
            const threatCategories = [...new Set(campaign.map(c => c.threatCategory))];
            const threatVerdicts = [...new Set(campaign.map(c => c.verdict))];

            // Generate campaign ID
            const campaignId = `CAMP-SIH-${Date.now().toString().slice(-6)}-${campaignIndex + 1}`;

            // Determine common traits for display
            let commonTraits = [];
            if (senderDomains.length === 1 && senderDomains[0]) commonTraits.push(`Sender: ${senderDomains[0]}`);
            if (originASNs.length === 1 && originASNs[0]) commonTraits.push(`Origin: ${originASNs[0]}`);
            if (threatCategories.length === 1 && threatCategories[0]) commonTraits.push(`Type: ${threatCategories[0]}`);
            if (threatVerdicts.length === 1 && threatVerdicts[0]) commonTraits.push(`Risk: ${threatVerdicts[0]}`);

            const commonTraitsText = commonTraits.length > 0 ? commonTraits.join(' • ') : 'Shared attack patterns';

            html += `
                <tr class="campaign-header">
                    <td colspan="7">
                        <div class="campaign-card">
                            <div class="campaign-header-row">
                                <span class="campaign-id">${campaignId}</span>
                                <span class="campaign-toggle" onclick="window.appController.toggleCampaign(${campaignIndex})">▼</span>
                            </div>
                            <div class="campaign-meta">
                                <span>${campaign.length} emails • ${new Date(earliest).toLocaleDateString()} - ${new Date(latest).toLocaleDateString()}</span>
                            </div>
                            <div class="campaign-traits">
                                <span>${commonTraitsText}</span>
                            </div>
                        </div>
                    </td>
                </tr>
            `;

            // Add campaign body (initially collapsed)
            html += `
                <tr class="campaign-body" id="campaign-body-${campaignIndex}" style="display: none;">
                    <td colspan="7">
                        <div class="campaign-content">
                            ${campaign.map((c, caseIndex) => `
                                <div class="campaign-case">
                                    <div class="case-id">${c.id}</div>
                                    <div class="case-subject">${this.escapeHtml(c.subject)}</div>
                                    <div class="case-details">
                                        <span>From: ${this.escapeHtml(c.sender)}</span>
                                        <span>•</span>
                                        <span>📍 ${c.origin}</span>
                                        <span>•</span>
                                        <span>${c.verdict} (${c.score}/100)</span>
                                    </div>
                                    <div class="case-actions">
                                        <button class="btn-xs btn-inspect" onclick="window.appController.loadCaseByIndex(${this.cases.indexOf(c)})">Inspect</button>
                                        <button class="btn-xs btn-delete" onclick="window.appController.deleteCaseByIndex(${this.cases.indexOf(c)})">Delete</button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </td>
                </tr>
            `;
        });

        container.innerHTML = html;
    }

    /**
     * Group cases into campaigns based on similarity
     * @param {Array} cases - Array of case objects
     * @param {number} threshold - Similarity threshold (0-1) for grouping
     * @returns {Array} - Array of campaign arrays
     */
    groupCasesIntoCampaigns(cases, threshold = 0.6) {
        const campaigns = [];
        const used = new Set();

        for (let i = 0; i < cases.length; i++) {
            if (used.has(i)) continue;

            // Start new campaign with case i
            const currentCampaign = [cases[i]];
            used.add(i);

            // Find similar cases to add to this campaign
            for (let j = i + 1; j < cases.length; j++) {
                if (used.has(j)) continue;

                const similarity = window.forensicEngine.calculateCaseSimilarity(cases[i], cases[j]);
                if (similarity >= threshold) {
                    currentCampaign.push(cases[j]);
                    used.add(j);
                }
            }

            if (currentCampaign.length > 0) {
                campaigns.push(currentCampaign);
            }
        }

        return campaigns;
    }

    /**
     * Toggle campaign expansion/collapse
     * @param {number} campaignIndex - Index of campaign to toggle
     */
    toggleCampaign(campaignIndex) {
        const bodyElement = document.getElementById(`campaign-body-${campaignIndex}`);
        if (!bodyElement) return;

        const isHidden = bodyElement.style.display === 'none';
        bodyElement.style.display = isHidden ? 'table-row' : 'none';

        // Update toggle icon
        const toggleIcon = bodyElement.previousElementSibling.querySelector('.campaign-toggle');
        if (toggleIcon) {
            toggleIcon.textContent = isHidden ? '▲' : '▼';
        }
    }

    loadCaseByIndex(index) {
        const c = this.cases[index];
        if (c) {
            document.getElementById("rawEmailInput").value = c.raw;
            this.switchTab("view-analyzer");
            this.runAnalysis();
        }
    }

    deleteCaseByIndex(index) {
        if (confirm("Remove this case record from incident database?")) {
            this.cases.splice(index, 1);
            localStorage.setItem("sentinel_mail_cases", JSON.stringify(this.cases));
            this.renderSavedCases();
        }
    }

    exportJSON() {
        if (!this.currentScan) {
            alert("No scan data available to export.");
            return;
        }

        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.currentScan, null, 2));
        const downloadAnchor = document.createElement("a");
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `sentinel-forensic-report-${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    }

    generatePrintReport() {
        if (!this.currentScan) {
            alert("Run an email analysis first before generating the official forensic report.");
            return;
        }

        const res = this.currentScan;
        const modal = document.getElementById("reportModal");
        const reportContent = document.getElementById("reportModalBody");

        if (!modal || !reportContent) return;

        reportContent.innerHTML = `
            <div class="print-doc">
                <div class="print-header">
                    <div class="print-agency">
                        <h2>NATIONAL CYBER FORENSICS & THREAT INTELLIGENCE</h2>
                        <h4>INCIDENT INVESTIGATION & DIGITAL EVIDENCE DOSSIER</h4>
                        <p>Smart India Hackathon (SIH) Specialized Security Module</p>
                    </div>
                    <div class="print-meta">
                        <p><strong>CASE REF:</strong> <code>SIH-FOR-${Date.now().toString().slice(-8)}</code></p>
                        <p><strong>TIMESTAMP:</strong> ${res.analyzedAt}</p>
                        <p><strong>SECURITY CLASSIFICATION:</strong> OFFICIAL / LAW ENFORCEMENT SENSITIVE</p>
                    </div>
                </div>

                <hr class="print-divider" />

                <div class="print-section">
                    <h3>1. EXECUTIVE THREAT SUMMARY</h3>
                    <table class="print-table">
                        <tr><td><strong>THREAT VERDICT</strong></td><td><span class="print-badge print-${res.threatSummary.verdict.toLowerCase()}">${res.threatSummary.verdict} (Risk Index: ${res.threatSummary.score}/100)</span></td></tr>
                        <tr><td><strong>CLASSIFICATION</strong></td><td>${res.threatSummary.category}</td></tr>
                        <tr><td><strong>CLAIMED SENDER</strong></td><td>${res.auth.from.name} &lt;${res.auth.from.email}&gt;</td></tr>
                        <tr><td><strong>BOUNCE RETURN PATH</strong></td><td>&lt;${res.auth.returnPath.email}&gt;</td></tr>
                        <tr><td><strong>AUTHENTICATION INTEGRITY</strong></td><td>SPF: ${res.auth.spf.status} | DKIM: ${res.auth.dkim.status} | DMARC: ${res.auth.dmarc.status}</td></tr>
                        <tr><td><strong>IDENTIFIED ANOMALIES</strong></td><td>${res.threatSummary.threatFactors.join("<br/>• ")}</td></tr>
                    </table>
                </div>

                <div class="print-section">
                    <h3>2. ORIGIN INFRASTRUCTURE & GEOLOCATION TRACE</h3>
                    <table class="print-table">
                        <tr><td><strong>EARLIEST SOURCE IP</strong></td><td><code>${res.originGeo ? res.originGeo.ip : 'N/A'}</code></td></tr>
                        <tr><td><strong>ESTIMATED LOCATION</strong></td><td>${res.originGeo ? res.originGeo.city + ', ' + res.originGeo.country : 'Unknown'}</td></tr>
                        <tr><td><strong>INTERNET SERVICE PROVIDER</strong></td><td>${res.originGeo ? res.originGeo.isp : 'Unknown'}</td></tr>
                        <tr><td><strong>AUTONOMOUS SYSTEM (ASN)</strong></td><td>${res.originGeo ? res.originGeo.asn : 'Unknown'}</td></tr>
                        <tr><td><strong>ANONYMITY / PROXY FLAGS</strong></td><td>${res.originGeo && res.originGeo.tor ? 'CONFIRMED TOR EXIT NODE' : (res.originGeo && res.originGeo.vpn ? 'COMMERCIAL VPN GATEWAY' : 'STANDARD HOST')}</td></tr>
                        <tr><td><strong>RELAY HOPS COUNT</strong></td><td>${res.hops.length} Mail Relay Hops Recorded in Received Chain</td></tr>
                    </table>
                </div>

                <div class="print-section">
                    <h3>3. AI & NATURAL LANGUAGE PROCESSING (NLP) HEURISTICS</h3>
                    <table class="print-table">
                        <tr><td><strong>URGENCY INDEX</strong></td><td>${res.nlp.urgencyScore}% (Matched: ${res.nlp.matchedUrgency.join(", ") || "None"})</td></tr>
                        <tr><td><strong>FINANCIAL / WIRE FRAUD CUES</strong></td><td>${res.nlp.financialScore}% (Matched: ${res.nlp.matchedFinancial.join(", ") || "None"})</td></tr>
                        <tr><td><strong>CREDENTIAL HARVESTING CUES</strong></td><td>${res.nlp.credentialScore}% (Matched: ${res.nlp.matchedCredentials.join(", ") || "None"})</td></tr>
                        <tr><td><strong>BEC EXECUTIVE IMPERSONATION</strong></td><td>${res.nlp.isBEC ? 'POSITIVE (High-Risk Wire/NDA Fraud Signature)' : 'NEGATIVE'}</td></tr>
                    </table>
                </div>

                <div class="print-section">
                    <h3>4. DIGITAL CHAIN OF CUSTODY & EVIDENCE INTEGRITY</h3>
                    <table class="print-table">
                        <tr><td><strong>SHA-256 HASH</strong></td><td><code class="break-hash">${res.hashes.sha256}</code></td></tr>
                        <tr><td><strong>MD5 CHECKSUM</strong></td><td><code>${res.hashes.md5}</code></td></tr>
                        <tr><td><strong>RAW PAYLOAD LENGTH</strong></td><td>${res.hashes.payloadLength} octets</td></tr>
                        <tr><td><strong>EVIDENTIARY VERIFICATION</strong></td><td>Cryptographically hashed at ingestion. Tamper-evident record generated per ISO/IEC 27037 forensic guidelines.</td></tr>
                    </table>
                </div>

                <div class="print-footer">
                    <p>Report generated by SentinelMail AI Forensic Intelligence Platform. Certified for cyber incident response and evidentiary documentation.</p>
                </div>
            </div>
        `;

        modal.style.display = "flex";

        const closeBtn = document.getElementById("closeReportModal");
        if (closeBtn) closeBtn.onclick = () => modal.style.display = "none";

        const triggerPrintBtn = document.getElementById("triggerPrintBtn");
        if (triggerPrintBtn) triggerPrintBtn.onclick = () => window.print();
    }

    copyEvidenceHash() {
        if (!this.currentScan) return;
        navigator.clipboard.writeText(this.currentScan.hashes.sha256).then(() => {
            const btn = document.getElementById("copyHashBtn");
            if (btn) {
                const orig = btn.innerText;
                btn.innerText = "Copied!";
                setTimeout(() => btn.innerText = orig, 1500);
            }
        });
    }

    escapeHtml(text) {
        if (!text) return "";
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// Global App Instance
window.addEventListener("DOMContentLoaded", () => {
    window.appController = new AppController();
    window.appController.init();
});
