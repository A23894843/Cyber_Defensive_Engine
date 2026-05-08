/**
 * Cyber Defensive Engine - Core Dashboard Logic
 * Handles real-time telemetry, ML status, PQC logs, and UI updates.
 */

// Initialize Timestamp
document.getElementById('init-time').innerText = `[${new Date().toLocaleTimeString()}]`;

// Global Tracking Variables
let previousAttacks = 0;
let previousBlocked = 0;
let peakCpu = 0;
let peakRam = 0;
let isFirstLoad = true;

// --- 1. Initialize Chart.js Instances ---

// Traffic Line Chart
const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctxTraffic, {
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
        responsive: true, 
        maintainAspectRatio: false, 
        plugins: { legend: { display: false } }, 
        scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } } 
    }
});

// Threat Gauge Chart (Doughnut)
const ctxGauge = document.getElementById('gaugeChart').getContext('2d');
const gaugeChart = new Chart(ctxGauge, {
    type: 'doughnut',
    data: { 
        datasets: [{ 
            data: [0, 100], 
            backgroundColor: ['#238636', '#30363d'], 
            borderWidth: 0,
            cutout: '80%' 
        }] 
    },
    options: { 
        rotation: -90, 
        circumference: 180, 
        maintainAspectRatio: false,
        plugins: { tooltip: { displayColors: false } } 
    }
});

// --- 2. Helper Functions ---

// Adds a new entry to the Live Activity Log
function addLogEntry(message, typeClass) {
    const logList = document.getElementById('event-log');
    const li = document.createElement('li');
    const timeStr = new Date().toLocaleTimeString();
    
    li.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="${typeClass}">${message}</span>`;
    logList.prepend(li);
    
    // Keep a maximum of 20 logs to prevent memory leaks
    if (logList.children.length > 20) {
        logList.removeChild(logList.lastChild);
    }
}

// --- 3. Main Data Fetch and UI Update Loop ---

async function refreshDashboardData() {
    try {
        // Fetch JSON data from Flask Backend
        const response = await fetch('/dashboard', { 
            headers: { 'X-Requested-With': 'XMLHttpRequest' } 
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        const s = data.stats; 

        // ---------------------------------------------------------
        // A. Process Subsystem Status (ML Training)
        // ---------------------------------------------------------
        const mlStatusObj = document.getElementById('ml-status');
        const badgeObj = document.getElementById('main-status-badge');
        const dotObj = document.getElementById('main-status-dot');
        const textObj = document.getElementById('main-status-text');

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

        // ---------------------------------------------------------
        // B. Process Dynamic Log Monitors
        // ---------------------------------------------------------
        if (s.logs && isFirstLoad) {
            const logContainer = document.getElementById('log-monitors');
            logContainer.innerHTML = ''; // Clear defaults
            s.logs.forEach(logFile => {
                const span = document.createElement('span');
                span.className = 'tag';
                span.innerText = logFile.split('/').pop(); // Show only filename (e.g., auth.log)
                logContainer.appendChild(span);
            });
        }

        // ---------------------------------------------------------
        // C. Update Blocked IPs List
        // ---------------------------------------------------------
        if (s.blocked_list) {
            const ipList = document.getElementById('blocked-ip-list');
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

        // ---------------------------------------------------------
        // D. Update Core Metrics & Peaks
        // ---------------------------------------------------------
        if (s.cpu > peakCpu) peakCpu = s.cpu;
        if (s.ram > peakRam) peakRam = s.ram;

        document.getElementById('live-cpu-table').innerText = s.cpu.toFixed(1);
        document.getElementById('peak-cpu').innerText = peakCpu.toFixed(1);
        
        document.getElementById('ram-util').innerText = s.ram.toFixed(1) + '%';
        document.getElementById('peak-ram').innerText = peakRam.toFixed(1);
        
        document.getElementById('risk-score').innerText = s.cpu.toFixed(1) + '%';
        document.getElementById('attack-count').innerText = s.attacks;
        document.getElementById('blocked-count').innerText = s.blocked;

        // ---------------------------------------------------------
        // E. Event Logging Logic
        // ---------------------------------------------------------
        if (!isFirstLoad) {
            if (s.attacks > previousAttacks) {
                const diff = s.attacks - previousAttacks;
                addLogEntry(`⚠️ Detected ${diff} new attack signature(s).`, 'log-warning');
            }
            if (s.blocked > previousBlocked) {
                const diff = s.blocked - previousBlocked;
                addLogEntry(`🛡️ Mitigated! Blocked ${diff} malicious IP(s).`, 'log-success');
            }
            if (previousBlocked > s.blocked) {
                addLogEntry(`🔓 Cooldown complete. IP(s) removed from firewall.`, 'log-info');
            }
        }
        
        previousAttacks = s.attacks;
        previousBlocked = s.blocked;
        isFirstLoad = false; // Initial load finished
        
        // ---------------------------------------------------------
        // F. Update Visual Bars and Charts
        // ---------------------------------------------------------
        document.getElementById('anomaly-text').innerText = s.attacks + '%';
        document.getElementById('anomaly-bar').style.width = Math.min(s.attacks, 100) + '%';

        // Update Line Chart
        trafficChart.data.datasets[0].data.push(s.cpu);
        trafficChart.data.datasets[0].data.shift(); 
        trafficChart.update('none'); // Use 'none' for smooth animation

        // Update Threat Gauge
        let threatLevel = Math.min(s.attacks * 2, 100); 
        let gaugeColor = '#238636'; 
        let labelText = "System Safe";

        if (threatLevel > 70) {
            gaugeColor = '#da3633'; 
            labelText = "CRITICAL THREAT";
        } else if (threatLevel > 40) {
            gaugeColor = '#e3b341'; 
            labelText = "Elevated Risk";
        } else if (threatLevel > 10) {
            gaugeColor = '#58a6ff'; 
            labelText = "Active Monitoring";
        }

        gaugeChart.data.datasets[0].data = [threatLevel, 100 - threatLevel];
        gaugeChart.data.datasets[0].backgroundColor = [gaugeColor, '#30363d'];
        gaugeChart.update();
        
        const labelElement = document.getElementById('gauge-label');
        labelElement.innerText = labelText;
        labelElement.style.color = gaugeColor;

    } catch (error) {
        console.error("Dashboard update failed:", error);
        document.getElementById('gauge-label').innerText = "Connection Lost";
        document.getElementById('gauge-label').style.color = "var(--text-muted)";
        document.getElementById('main-status-text').innerText = "Offline";
        document.getElementById('main-status-dot').className = "pulse-dot training";
        document.getElementById('main-status-dot').style.backgroundColor = "var(--accent-red)";
    }
}

// --- 4. Execution Loop ---
// Fetch new data every 2 seconds
setInterval(refreshDashboardData, 2000);

// Fetch immediately on page load
window.onload = refreshDashboardData;