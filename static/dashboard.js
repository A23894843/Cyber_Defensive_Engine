/**
 * Cyber Defensive Engine - Core Dashboard Logic
 * Handles real-time telemetry, ML status, PQC logs, SQLite Database records, and UI updates.
 */

document.addEventListener("DOMContentLoaded", () => {

    /*
     * CSS Theme Toggle Script
     */
    const toggle = document.getElementById("themeToggle");
    if (toggle) {
        if(localStorage.getItem("theme") === "light"){ document.body.classList.add("light-theme"); }
        toggle.addEventListener("click", () => {
            document.body.classList.toggle("light-theme");
            if(document.body.classList.contains("light-theme")){ localStorage.setItem("theme","light"); }
            else{ localStorage.setItem("theme","dark"); }
        });
    }

    /*
     * Core AJAX Application Logic & Charts
     */
    const initTimeEl = document.getElementById('init-time');
    if (initTimeEl) initTimeEl.innerText = `[${new Date().toLocaleTimeString()}]`;

    let previousAttacks = 0;
    let previousBlocked = 0;
    let peakCpu = 0;
    let peakRam = 0;
    let isFirstLoad = true;

    // --- 1. Initialize Chart.js Instances ---
    let trafficChart, gaugeChart;
    
    const trafficCanvas = document.getElementById('trafficChart');
    if (trafficCanvas) {
        const ctxTraffic = trafficCanvas.getContext('2d');
        trafficChart = new Chart(ctxTraffic, {
            type: 'line',
            data: { 
                labels: ['', '', '', '', '', '', '', '', '', ''], 
                datasets: [{ 
                    data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 
                    borderColor: '#238636', 
                    borderWidth: 2, 
                    fill: true,
                    backgroundColor: 'rgba(35, 134, 54, 0.1)',
                    pointRadius: 0,
                    tension: 0.4
                }] 
            },
            options: { 
                responsive: true, maintainAspectRatio: false, 
                plugins: { legend: { display: false } }, 
                scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } } 
            }
        });
    }

    const gaugeCanvas = document.getElementById('gaugeChart');
    if (gaugeCanvas) {
        const ctxGauge = gaugeCanvas.getContext('2d');
        gaugeChart = new Chart(ctxGauge, {
            type: 'doughnut',
            data: { 
                datasets: [{ 
                    data: [0, 100], 
                    backgroundColor: ['#238636', '#30363d'], 
                    borderWidth: 0, cutout: '80%' 
                }] 
            },
            options: { 
                rotation: -90, circumference: 180, maintainAspectRatio: false,
                plugins: { tooltip: { displayColors: false } } 
            }
        });
    }

    // --- 2. Live Notification Helper ---
    function addLogEntry(message, typeClass) {
        const logList = document.getElementById('event-log');
        if (!logList) return;
        const li = document.createElement('li');
        const timeStr = new Date().toLocaleTimeString();
        li.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="${typeClass}">${message}</span>`;
        logList.prepend(li);
        if (logList.children.length > 20) logList.removeChild(logList.lastChild);
    }

    // --- 3. Main Data Fetch and Dynamic UI Sync ---
    async function refreshDashboardData() {
        try {
            const response = await fetch('/dashboard', { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            
            // Fix: Handle Flask Login Redirects properly so it doesn't crash trying to parse HTML
            if (response.redirected || response.url.includes('/login')) {
                window.location.href = '/login';
                return;
            }

            if (!response.ok) throw new Error('Network response was not ok');
            
            const data = await response.json();
            const s = data.stats; 
            if (!s) return; // Guard clause

            // Render SQLite Database History
            if (s.attack_history) {
                const historyTbody = document.getElementById('attack-history-table');
                if(historyTbody){
                    historyTbody.innerHTML = ''; 
                    
                    if (s.attack_history.length === 0) {
                        historyTbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:15px; color:var(--muted);">No attack history recorded in the database.</td></tr>';
                    } else {
                        s.attack_history.forEach(entry => {
                            let badgeColor = 'var(--primary)'; // Default theme
                            if (entry.type && entry.type.includes('SCAN')) badgeColor = 'var(--yellow)';
                            if (entry.type && (entry.type.includes('ANOMALY') || entry.type.includes('INTRUSION'))) badgeColor = 'var(--red)';
                            if (entry.type && entry.type.includes('UNBLOCK')) badgeColor = 'var(--green)';

                            historyTbody.innerHTML += `
                                <tr>
                                    <td style="color:var(--muted);">${entry.timestamp || 'N/A'}</td>
                                    <td style="font-family:monospace; color:var(--red); font-weight:600;">${entry.ip || 'Local/Internal'}</td>
                                    <td><span class="tag" style="background:rgba(255,255,255,0.05); color:${badgeColor}; margin:0;">${entry.type || 'UNKNOWN'}</span></td>
                                    <td style="color:var(--text);">${entry.desc || ''}</td>
                                </tr>`;
                        });
                    }
                }
            }

            // Sync Machine Learning Training State
            const mlStatusObj = document.getElementById('ml-status');
            const badgeObj = document.getElementById('main-status-badge');
            const dotObj = document.getElementById('main-status-dot');
            const textObj = document.getElementById('main-status-text');

            if (mlStatusObj && badgeObj && dotObj && textObj) {
                if (s.is_training) {
                    mlStatusObj.innerText = "Isolation Forest: Training Baseline...";
                    mlStatusObj.style.color = "var(--accent-yellow)";
                    badgeObj.className = "status-badge training";
                    dotObj.className = "pulse-dot training";
                    textObj.innerText = "System Learning";
                } else {
                    mlStatusObj.innerText = "Isolation Forest: Active Detection";
                    mlStatusObj.style.color = "var(--accent-green)";
                    badgeObj.className = "status-badge";
                    dotObj.className = "pulse-dot";
                    textObj.innerText = "System Live";
                }
            }

            if (s.logs && isFirstLoad) {
                const logContainer = document.getElementById('log-monitors');
                if (logContainer) {
                    logContainer.innerHTML = ''; 
                    s.logs.forEach(logFile => {
                        const span = document.createElement('span');
                        span.className = 'tag';
                        span.innerText = logFile.split('/').pop(); 
                        logContainer.appendChild(span);
                    });
                }
            }

            if (s.blocked_list) {
                const ipList = document.getElementById('blocked-ip-list');
                if (ipList) {
                    if (s.blocked_list.length === 0) {
                        ipList.innerHTML = '<li style="color: var(--text-muted); border: none;">No malicious IPs currently blocked.</li>';
                    } else {
                        ipList.innerHTML = '';
                        s.blocked_list.forEach(ip => {
                            const li = document.createElement('li');
                            li.innerText = "🛑 " + ip;
                            ipList.appendChild(li);
                        });
                    }
                }
            }

            // High Water Marks tracking
            if (s.cpu > peakCpu) peakCpu = s.cpu;
            if (s.ram > peakRam) peakRam = s.ram;

            // Safe update wrapper for simple text elements
            const safeUpdate = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
            
            safeUpdate('live-cpu-table', (s.cpu || 0).toFixed(1));
            safeUpdate('peak-cpu', peakCpu.toFixed(1));
            safeUpdate('ram-util', (s.ram || 0).toFixed(1) + '%');
            safeUpdate('peak-ram', peakRam.toFixed(1));
            safeUpdate('risk-score', (s.cpu || 0).toFixed(1) + '%');
            safeUpdate('attack-count', s.attacks || 0);
            safeUpdate('blocked-count', s.blocked || 0);

            // Generate event notifications dynamically
            if (!isFirstLoad) {
                if (s.attacks > previousAttacks) addLogEntry(`⚠️ Detected ${s.attacks - previousAttacks} new attack signature(s).`, 'log-warning');
                if (s.blocked > previousBlocked) addLogEntry(`🛡️ Mitigated! Blocked ${s.blocked - previousBlocked} malicious IP(s).`, 'log-success');
                if (previousBlocked > s.blocked) addLogEntry(`🔓 Cooldown complete. IP(s) removed from firewall.`, 'log-info');
            }
            
            previousAttacks = s.attacks || 0;
            previousBlocked = s.blocked || 0;
            isFirstLoad = false; 
            
            safeUpdate('anomaly-text', previousAttacks + '%');
            const anomalyBar = document.getElementById('anomaly-bar');
            if (anomalyBar) anomalyBar.style.width = Math.min(previousAttacks, 100) + '%';

            if (trafficChart && s.cpu !== undefined) {
                trafficChart.data.datasets[0].data.push(s.cpu);
                trafficChart.data.datasets[0].data.shift(); 
                trafficChart.update('none'); 
            }

            if (gaugeChart) {
                let threatLevel = Math.min(previousAttacks * 2, 100); 
                let gaugeColor = '#238636'; 
                let labelText = "System Safe";

                if (threatLevel > 70) {
                    gaugeColor = '#da3633'; labelText = "CRITICAL THREAT";
                } else if (threatLevel > 40) {
                    gaugeColor = '#e3b341'; labelText = "Elevated Risk";
                } else if (threatLevel > 10) {
                    gaugeColor = '#58a6ff'; labelText = "Active Monitoring";
                }

                gaugeChart.data.datasets[0].data = [threatLevel, 100 - threatLevel];
                gaugeChart.data.datasets[0].backgroundColor = [gaugeColor, '#30363d'];
                gaugeChart.update();
                
                const labelElement = document.getElementById('gauge-label');
                if (labelElement) {
                    labelElement.innerText = labelText;
                    labelElement.style.color = gaugeColor;
                }
            }

        } catch (error) {
            console.error("Dashboard update failed:", error);
            const safeUpdateState = (id, text, color, className) => {
                const el = document.getElementById(id);
                if (el) {
                    if (text) el.innerText = text;
                    if (color) el.style.color = color;
                    if (className) el.className = className;
                }
            };
            safeUpdateState('gauge-label', "Connection Lost", "var(--text-muted)");
            safeUpdateState('main-status-text', "Offline");
            safeUpdateState('main-status-dot', null, "var(--accent-red)", "pulse-dot training");
            const dot = document.getElementById('main-status-dot');
            if(dot) dot.style.backgroundColor = "var(--red)";
        }
    }

    // Start execution loop instantly upon load, then run every 2s
    refreshDashboardData();
    setInterval(refreshDashboardData, 2000);

});
