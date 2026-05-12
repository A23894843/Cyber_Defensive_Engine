/**
 * Cyber Defensive Engine - Core Dashboard Logic
 * Handles real-time telemetry, ML status, PQC logs, and UI updates.
 * * NOTE FOR PROJECT REPORT: 
 * This module operates as the primary frontend controller. It uses an asynchronous 
 * polling mechanism to fetch system state from the Flask backend and dynamically 
 * updates DOM elements and Chart.js instances to provide real-time situational awareness.
 */

// Initialize Timestamp
// Captures the exact moment the dashboard is loaded for the user session
document.getElementById('init-time').innerText = `[${new Date().toLocaleTimeString()}]`;

// Global Tracking Variables
// These variables maintain state between polling intervals to calculate deltas (changes)
let previousAttacks = 0; // Tracks the last known total of attacks to detect new ones
let previousBlocked = 0; // Tracks the last known total of blocked IPs
let peakCpu = 0;         // Records the maximum CPU usage observed during the session
let peakRam = 0;         // Records the maximum RAM usage observed during the session
let isFirstLoad = true;  // Flag to prevent triggering alert notifications on the initial data load

// --- 1. Initialize Chart.js Instances ---

// Traffic Line Chart
// Renders a real-time visualization of system resource usage (CPU) over time
const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: { 
        // Pre-fill labels array to maintain a fixed 10-point window on the X-axis
        labels: ['', '', '', '', '', '', '', '', '', ''], 
        datasets: [{ 
            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 
            borderColor: '#238636', // Primary theme green
            borderWidth: 2, 
            fill: true,
            backgroundColor: 'rgba(35, 134, 54, 0.1)', // Semi-transparent fill under the line
            pointRadius: 0, // Hide data points for a smoother wave effect
            tension: 0.4    // Bezier curve tension for visual smoothing
        }] 
    },
    options: { 
        responsive: true, 
        maintainAspectRatio: false, 
        plugins: { legend: { display: false } }, // Hide legend to save UI space
        scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } } 
    }
});

// Threat Gauge Chart (Doughnut)
// Acts as a speedometer-style gauge to indicate overall system risk/threat level
const ctxGauge = document.getElementById('gaugeChart').getContext('2d');
const gaugeChart = new Chart(ctxGauge, {
    type: 'doughnut',
    data: { 
        datasets: [{ 
            data: [0, 100], // Initial state: 0% threat, 100% safe
            backgroundColor: ['#238636', '#30363d'], 
            borderWidth: 0,
            cutout: '80%' // Makes the doughnut thin to resemble a gauge
        }] 
    },
    options: { 
        rotation: -90, // Start drawing from the left side (half-circle)
        circumference: 180, // Restrict the chart to a semi-circle
        maintainAspectRatio: false,
        plugins: { tooltip: { displayColors: false } } 
    }
});

// --- 2. Helper Functions ---

// Adds a new entry to the Live Activity Log
// Dynamically creates DOM elements and manages the log stack
function addLogEntry(message, typeClass) {
    const logList = document.getElementById('event-log');
    const li = document.createElement('li');
    const timeStr = new Date().toLocaleTimeString();
    
    // Construct the log entry HTML with a timestamp and the specific message style
    li.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="${typeClass}">${message}</span>`;
    logList.prepend(li); // Insert the newest log at the top of the list
    
    // Keep a maximum of 20 logs to prevent memory leaks
    // Automatically removes the oldest entry (at the bottom) if the limit is exceeded
    if (logList.children.length > 20) {
        logList.removeChild(logList.lastChild);
    }
}

// --- 3. Main Data Fetch and UI Update Loop ---

// Core asynchronous function that orchestrates data retrieval and UI synchronization
async function refreshDashboardData() {
    try {
        // Fetch JSON data from Flask Backend
        // Includes 'X-Requested-With' header to indicate an AJAX request to the server
        const response = await fetch('/dashboard', { 
            headers: { 'X-Requested-With': 'XMLHttpRequest' } 
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        const s = data.stats; // Extract the stats payload

        // ---------------------------------------------------------
        // A. Process Subsystem Status (ML Training)
        // ---------------------------------------------------------
        // Updates the UI badges and text based on the Machine Learning model's state
        const mlStatusObj = document.getElementById('ml-status');
        const badgeObj = document.getElementById('main-status-badge');
        const dotObj = document.getElementById('main-status-dot');
        const textObj = document.getElementById('main-status-text');

        if (s.is_training) {
            // Model is currently establishing a baseline (training phase)
            mlStatusObj.innerText = "Isolation Forest: Training Baseline...";
            mlStatusObj.style.color = "var(--accent-yellow)";
            badgeObj.className = "status-badge training";
            dotObj.className = "pulse-dot training";
            textObj.innerText = "System Learning";
        } else {
            // Model is actively monitoring network traffic (production phase)
            mlStatusObj.innerText = "Isolation Forest: Active Detection";
            mlStatusObj.style.color = "var(--accent-green)";
            badgeObj.className = "status-badge";
            dotObj.className = "pulse-dot";
            textObj.innerText = "System Live";
        }

        // ---------------------------------------------------------
        // B. Process Dynamic Log Monitors
        // ---------------------------------------------------------
        // Displays the actual log files the system is currently parsing
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
        // Re-renders the firewall blocklist panel based on active bans
        if (s.blocked_list) {
            const ipList = document.getElementById('blocked-ip-list');
            if (s.blocked_list.length === 0) {
                // Display placeholder if no threats are currently blocked
                ipList.innerHTML = '<li style="color: var(--text-muted); border: none;">No malicious IPs currently blocked.</li>';
            } else {
                ipList.innerHTML = ''; // Clear list
                // Populate the UI list with newly blocked IP addresses
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
        // Maintain high-water marks (peaks) for system resources
        if (s.cpu > peakCpu) peakCpu = s.cpu;
        if (s.ram > peakRam) peakRam = s.ram;

        // Update textual metric readouts on the dashboard grid
        document.getElementById('live-cpu-table').innerText = s.cpu.toFixed(1);
        document.getElementById('peak-cpu').innerText = peakCpu.toFixed(1);
        
        document.getElementById('ram-util').innerText = s.ram.toFixed(1) + '%';
        document.getElementById('peak-ram').innerText = peakRam.toFixed(1);
        
        // Map CPU directly to risk score (or adjust algorithmically as needed)
        document.getElementById('risk-score').innerText = s.cpu.toFixed(1) + '%';
        
        document.getElementById('attack-count').innerText = s.attacks;
        document.getElementById('blocked-count').innerText = s.blocked;

        // ---------------------------------------------------------
        // E. Event Logging Logic
        // ---------------------------------------------------------
        // Compares current data to previous poll data to generate contextual alerts
        if (!isFirstLoad) {
            if (s.attacks > previousAttacks) {
                // If attacks increased, calculate the delta and generate a warning log
                const diff = s.attacks - previousAttacks;
                addLogEntry(`⚠️ Detected ${diff} new attack signature(s).`, 'log-warning');
            }
            if (s.blocked > previousBlocked) {
                // If blocks increased, calculate the delta and generate a success log
                const diff = s.blocked - previousBlocked;
                addLogEntry(`🛡️ Mitigated! Blocked ${diff} malicious IP(s).`, 'log-success');
            }
            if (previousBlocked > s.blocked) {
                // If the number of blocked IPs decreased, it means bans expired
                addLogEntry(`🔓 Cooldown complete. IP(s) removed from firewall.`, 'log-info');
            }
        }
        
        // Update state trackers for the next polling cycle
        previousAttacks = s.attacks;
        previousBlocked = s.blocked;
        isFirstLoad = false; // Initial load finished, allow logging going forward
        
        // ---------------------------------------------------------
        // F. Update Visual Bars and Charts
        // ---------------------------------------------------------
        // Update horizontal progress bar representing anomaly percentage
        document.getElementById('anomaly-text').innerText = s.attacks + '%';
        document.getElementById('anomaly-bar').style.width = Math.min(s.attacks, 100) + '%';

        // Update Line Chart (FIFO queue methodology)
        trafficChart.data.datasets[0].data.push(s.cpu); // Add new data point to the end
        trafficChart.data.datasets[0].data.shift(); // Remove oldest data point from the beginning
        trafficChart.update('none'); // Use 'none' for smooth animation without visual jumping

        // Update Threat Gauge
        // Calculate threat level (exaggerated by * 2 for visual impact, capped at 100%)
        let threatLevel = Math.min(s.attacks * 2, 100); 
        let gaugeColor = '#238636'; // Default Green (Safe)
        let labelText = "System Safe";

        // Determine severity tier and assign corresponding colors/labels
        if (threatLevel > 70) {
            gaugeColor = '#da3633'; // Red
            labelText = "CRITICAL THREAT";
        } else if (threatLevel > 40) {
            gaugeColor = '#e3b341'; // Yellow
            labelText = "Elevated Risk";
        } else if (threatLevel > 10) {
            gaugeColor = '#58a6ff'; // Blue
            labelText = "Active Monitoring";
        }

        // Apply updated values to the Doughnut chart instance
        gaugeChart.data.datasets[0].data = [threatLevel, 100 - threatLevel];
        gaugeChart.data.datasets[0].backgroundColor = [gaugeColor, '#30363d'];
        gaugeChart.update();
        
        // Update the text label residing underneath the gauge
        const labelElement = document.getElementById('gauge-label');
        labelElement.innerText = labelText;
        labelElement.style.color = gaugeColor;

    } catch (error) {
        // --- 5. Error Handling / Graceful Degradation ---
        // If the backend drops connection, visually indicate offline status to the user
        console.error("Dashboard update failed:", error);
        document.getElementById('gauge-label').innerText = "Connection Lost";
        document.getElementById('gauge-label').style.color = "var(--text-muted)";
        document.getElementById('main-status-text').innerText = "Offline";
        document.getElementById('main-status-dot').className = "pulse-dot training";
        document.getElementById('main-status-dot').style.backgroundColor = "var(--accent-red)";
    }
}

// --- 4. Execution Loop ---
// Set up asynchronous polling: Fetch new data every 2 seconds (2000 milliseconds)
setInterval(refreshDashboardData, 2000);

// Fetch immediately on page load to populate initial data without waiting 2 seconds
window.onload = refreshDashboardData;
