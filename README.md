Adaptive Cyber Defensive Engine (v1.0) 🛡️

The Adaptive Cyber Defensive Engine is a high-performance, AI-driven Intrusion Prevention System (IPS) designed to autonomously monitor network traffic, detect anomalies, and mitigate threats in real-time. It integrates low-level packet processing with Post-Quantum Cryptography (PQC) and Unsupervised Machine Learning to provide a robust defense against modern and future cyber threats.  

This project was developed by students at Gurukul Kangri (Deemed to be University) Vishwavidyalaya as part of the B.Tech Computer Science and Engineering program.
🚀 Key Features

    Post-Quantum Authenticated IPC: Data transmission between the C++ sensor and the analytical engine is secured using the NIST-standardized ML-DSA-44 (Dilithium2) digital signature algorithm, ensuring quantum-resistant integrity.  

Behavioral Anomaly Detection: Employs an Isolation Forest unsupervised ML model to identify zero-day attacks by establishing a 10-minute network traffic baseline based on packet sizes and frequencies.  

Deterministic Honeypot Integration: Features a specialized IPC channel (Named Pipe) that triggers immediate firewall blocks via iptables when aggressive port scanning is detected by the C++ sniffer.  

Live Log Behavior Monitoring: Continuously scans critical system files like /var/log/auth.log and syslog for suspicious patterns, including brute-force attempts and unauthorized permission escalations.  

Advanced Web Dashboard: A responsive Flask-powered interface utilizing Chart.js for real-time telemetry, threat assessment gauges, and an active blocked IP list.  

🛠️ System Architecture

The engine utilizes a hybrid architecture to maximize capture efficiency and analytical depth:

    Sensor Layer (sniffer.cpp): A high-speed C++ engine using libpcap to capture raw network packets and liboqs to sign data for secure transit.  

Communication Layer (IPC): Uses Unix Domain Sockets (UDS) for high-bandwidth packet streaming and Named Pipes (FIFO) for low-latency deterministic security alerts.  

Analytical Layer (main.py): The Python core responsible for Post-Quantum signature verification, ML model training, and executing automated mitigation rules.  

Interface Layer: A modern web UI that allows administrators to monitor system health and current threat levels from any device on the network.  

👥 Project Team

    Abhinandan (236301015)

    Amritanshu Mishra (236301039)

    Amul Jaiswal (236301040)

    Harshit (236301099)

    Project Supervisor: Mr. Kuldeep

🔧 Installation & Setup
Prerequisites

    Operating System: Linux (Kali Linux or Ubuntu recommended).

    Privileges: Root access required for packet capture and firewall modification.

1. Install System Dependencies
Bash

sudo apt update
sudo apt install libpcap-dev libssl-dev liboqs-dev g++ python3-venv

2. Setup the Python Environment
Bash

python3 -m venv .venv
source .venv/bin/activate
pip install Flask flask-mail psutil joblib scikit-learn numpy oqs

🚦 Usage

    Compile & Run: The system is designed to compile the sniffer and initialize itself automatically upon running the main script.  

Bash

sudo ./.venv/bin/python main.py

Initial Configuration: Open http://localhost:8000 (or your device's local IP) in a browser to complete the administrator registration and verify your session via PQC-signed email OTP.  

Training Phase: The engine will establish a baseline for 600 seconds (10 minutes) before entering active detection mode.  

Monitoring: Use the dashboard to view real-time traffic profiling and managed blocked IP addresses.  

⚠️ Disclaimer

This software is intended for educational research and defensive security testing in controlled environments. It performs automated modifications to system iptables rules. Use at your own risk.
