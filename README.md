# 🛡️ Adaptive Cyber Defensive Engine (v1.0)

The **Adaptive Cyber Defensive Engine** is a high-performance, AI-driven **Intrusion Prevention System (IPS)** designed to autonomously monitor network traffic, detect anomalies, and mitigate threats in real-time.

It integrates **low-level packet processing**, **Post-Quantum Cryptography (PQC)**, and **Unsupervised Machine Learning** to provide robust defense against modern and future cyber threats.

This project was developed by students at **Gurukul Kangri (Deemed to be University) Vishwavidyalaya** as part of the **B.Tech Computer Science and Engineering** program.

---

# 🚀 Key Features

## 🔐 Post-Quantum Authenticated IPC
Data transmission between the C++ sensor and the analytical engine is secured using the **NIST-standardized ML-DSA-44 (Dilithium2)** digital signature algorithm, ensuring quantum-resistant integrity.

---

## 🧠 Behavioral Anomaly Detection
Employs an **Isolation Forest** unsupervised machine learning model to identify zero-day attacks by establishing a **10-minute network traffic baseline** based on packet sizes and frequencies.

---

## 🚨 Deterministic Honeypot Integration
Features a specialized IPC channel (**Named Pipe/FIFO**) that triggers immediate firewall blocks via **iptables** when aggressive port scanning is detected by the C++ sniffer.

---

## 📄 Live Log Behavior Monitoring
Continuously scans critical system files like:

- `/var/log/auth.log`
- `/var/log/syslog`

for suspicious patterns including:

- Brute-force login attempts
- Unauthorized privilege escalation
- SSH anomalies
- Failed authentication events

---

## 🌐 Advanced Web Dashboard
A responsive **Flask-powered interface** utilizing **Chart.js** for:

- Real-time telemetry
- Threat assessment gauges
- Active blocked IP list
- Live activity logs
- Network behavior profiling

---

# 🛠️ System Architecture

The engine utilizes a hybrid architecture to maximize capture efficiency and analytical depth.

---

## ⚡ Sensor Layer (`sniffer.cpp`)
A high-speed C++ engine using:

- `libpcap` for raw packet capture
- `liboqs` for post-quantum digital signatures

Responsibilities:

- Packet sniffing
- Threat event generation
- IPC communication
- Honeypot monitoring

---

## 🔄 Communication Layer (IPC)

### Unix Domain Sockets (UDS)
Used for:

- High-bandwidth packet streaming
- Secure local communication

### Named Pipes (FIFO)
Used for:

- Low-latency deterministic alerts
- Honeypot event signaling

---

## 🧠 Analytical Layer (`main.py`)
The Python core responsible for:

- PQC signature verification
- ML model training
- Threat analysis
- Automated mitigation rules
- Firewall management

---

## 🖥️ Interface Layer
A modern responsive dashboard that allows administrators to monitor:

- System health
- Threat levels
- Active attacks
- CPU/RAM utilization
- Firewalled IP addresses

from any device on the network.

---

# 📂 Project Structure

```bash
Adaptive-Cyber-Defensive-Engine/
│
├── main.py
├── sniffer.cpp
├── config.py
├── model.pkl
├── Cyber_Defensive_Engine.log
│
├── static/
│   ├── logo.png
│   └── dashboard.js
│
├── templates/
│   ├── setup.html
│   ├── verify.html
│   └── dashboard.html
│
└── README.md
```

---

# 👥 Project Team

| Name | Roll Number |
|------|-------------|
| Abhinandan | 236301015 |
| Amritanshu Mishra | 236301039 |
| Amul Jaiswal | 236301040 |
| Harshit | 236301099 |

### 🎓 Project Supervisor
**Mr. Kuldeep**

---

# 🔧 Installation & Setup

## 📌 Prerequisites

### Operating System
- Kali Linux *(Recommended)*
- Ubuntu Linux

### Privileges
Root access is required for:

- Packet capture
- Firewall modification
- Log monitoring

---

# 1️⃣ Install System Dependencies

```bash
sudo apt update
sudo apt install libpcap-dev libssl-dev liboqs-dev g++ python3-venv
```

---

# 2️⃣ Setup Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

# 3️⃣ Install Python Dependencies

```bash
pip install Flask flask-mail psutil joblib scikit-learn numpy oqs
```

---

# 🚦 Usage

## ▶️ Start the Engine

```bash
sudo ./.venv/bin/python main.py
```

The system automatically:

- Compiles the C++ sniffer
- Initializes IPC channels
- Starts the Flask dashboard
- Begins traffic monitoring

---

# 🌐 Initial Configuration

Open the dashboard in your browser:

```bash
http://localhost:8000
```

or access via your local network IP:

```bash
http://<your-local-ip>:8000
```

Complete:

- Administrator registration
- Email verification
- PQC-signed OTP authentication

---

# 🧪 Training Phase

The engine enters a **600-second (10-minute)** training phase to establish a behavioral baseline.

During this period:

- Traffic patterns are analyzed
- Packet frequency statistics are learned
- Anomaly thresholds are calibrated

After training, the system automatically enters **Active Detection Mode**.

---

# 📊 Monitoring

The live dashboard provides:

- Real-time threat visualization
- CPU/RAM metrics
- Threat level gauge
- Active attack count
- Firewalled IP list
- Behavioral anomaly graphs
- Live security logs

---

# 🔒 Security Technologies Used

| Technology | Purpose |
|------------|---------|
| ML-DSA-44 (Dilithium2) | Post-Quantum Signatures |
| Isolation Forest | Anomaly Detection |
| iptables | Automated Firewall Blocking |
| Unix Domain Sockets | Secure IPC |
| Named Pipes (FIFO) | Honeypot Signaling |
| Flask | Web Interface |
| Chart.js | Data Visualization |

---

# 📈 Future Enhancements

- Deep Learning-based Threat Detection
- Distributed Sensor Nodes
- Real-Time Threat Intelligence Feeds
- SIEM Integration
- Docker/Kubernetes Deployment
- AI-based Malware Classification
- Advanced Threat Hunting Module

---

# ⚠️ Disclaimer

This software is intended strictly for:

- Educational research
- Defensive cybersecurity testing
- Controlled lab environments

The engine performs automated modifications to system firewall rules using `iptables`.

> Use responsibly and at your own risk.

---

# 📜 License

This project is intended for academic and educational purposes.

---

# ⭐ Acknowledgements

Special thanks to:

- Gurukul Kangri (Deemed to be University)
- Department of Computer Science & Engineering
- Open Quantum Safe (liboqs) Project
- Flask & Scikit-learn Communities

---
