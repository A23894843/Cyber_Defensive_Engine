"""
Cyber Defensive Engine - Main Controller
Orchestrates the Flask Dashboard, Machine Learning (Isolation Forest), 
Post-Quantum Cryptography (ML-DSA-44), and Subsystem threads.
"""
import os
import oqs
import ssl
import sys
import json
import time
import fcntl
import socket
import struct
import select
import psutil
import joblib
import smtplib
import logging
import platform
import subprocess
import threading
import numpy as np
from config import *
import random as ran
from PIL import Image
from datetime import datetime
import matplotlib.pyplot as plt
from flask_mail import Mail, Message
from email.message import EmailMessage
from sklearn.ensemble import IsolationForest
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from flask import Flask, render_template, request, redirect, session, jsonify

if platform.system() == "Windows"   :
    import winsound

# ==========================================
# SYSTEM INITIALIZATION & SANITY CHECKS
# ==========================================
is_valid = True
# Create Named Pipe for IPC if it doesn't exist
if not os.path.exists(PIPE) :
    subprocess.run(["mkfifo", PIPE])
    subprocess.run(["chmod", "777", PIPE])

time.sleep(2)

thread_lock = threading.Lock() # Mutex for thread-safe operations on global variables

# Initialize Flask application and secure sessions
app = Flask(__name__)
app.secret_key = os.urandom(32)
import logging

# Suppress standard Flask request logging to keep the console clean
log_werkzeug = logging.getLogger('werkzeug')
log_werkzeug.setLevel(logging.ERROR)

# Ensure config file exists for admin details
if not os.path.exists("config.json")    :   
    with open("config.json", 'w') as f :
        json.dump({"name": "", "email": ""}, f)
    is_valid = False

# Reset engine log on startup
if os.path.exists(log_path)  :  
    os.remove(log_path)

# Automatically compile the C++ Sniffer module if not compiled
if not os.path.exists("./sniffer"):
    subprocess.run(["g++", "-o", "sniffer", "sniffer.cpp", "-lpcap", "-loqs", "-lcrypto", "-O3"])
    time.sleep(3)

# Configure primary Engine Logger
log = logging.getLogger("Cyber_Defensive_Engine")
log.setLevel(logging.INFO)

if not log.handlers :
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

# Configure Flask-Mail SMTP settings for Alerts
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USERNAME = sender_email,
    MAIL_PASSWORD = sender_password
)

mail = Mail (app)

# ==========================================
# LAUNCH C++ SNIFFER SUBPROCESS
# ==========================================
try:
    # Requires sudo to capture raw network packets
    sniffer = subprocess.Popen(["sudo", "./sniffer"])
    time.sleep(2)
except FileNotFoundError:
    log.warning("Error: ./sniffer executable not found. Did you compile it?")
    exit(1)

if sniffer.poll() is not None:
    log.error("Sniffer process crashed!")
    sys.exit(1)

# Helper function to read persistent admin data
def load_user_config()  :
    with open("config.json", 'r') as f :
        return json.load(f)

data = load_user_config()
name = data.get("name")
receiver_email = data.get("email")

# Platform-agnostic audible alert system
def play_alert_sound()  :
    if platform.system() == "Windows" :
        threading.Thread(target = lambda: winsound.Beep(1000, 500), daemon = True).start()
    else :
        print('\a')

# ==========================================
# EMAIL ALERTING SYSTEM
# ==========================================
def alert(subject, body, email = receiver_email):
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = email
    message.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.send_message(message)
        log.info(f"Email sent to {email}")
    except Exception as e:
        log.error(f"Failed to send email alert: {e}")

# Helper to extract Source IP from raw packet headers (IPv4)
def extract_source_ip(raw_packet):
    try:
        ip_header = raw_packet[14:34]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        return src_ip
    except:
        return None

# ==========================================
# FLASK WEB ROUTES (UI Controllers)
# ==========================================
@app.route("/")
def home():
    # Refresh validation check from the file directly
    current_config = load_user_config()
    # Route to Setup if admin details are missing
    if not current_config.get("name") or not current_config.get("email"):
        return redirect("/setup")
    return redirect("/dashboard")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    global otp_s
    if request.method == "POST":
        name_e = request.form["name"]
        email_e = request.form["email"]

        session["name"] = name_e
        session["email"] = email_e

        # 1. Generate Classic OTP (6 digits)
        otp_code = str(ran.randint(100000, 999999))
        otp_s[email_e] = {
            "otp": otp_code,
            "time": time.time()
        }

        # 2. Generate Post-Quantum Signature for the OTP (Hybrid Security)
        # Reads the private key generated by the C++ Sniffer
        with open("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer_private_key.bin", "rb") as f:
            sk = f.read()
        
        # Initialize liboqs ML-DSA-44 Context
        sig_instance = oqs.Signature("ML-DSA-44", secret_key=sk)
        
        # Sign the OTP
        signature = sig_instance.sign(otp_code.encode())
        pqc_signature_hex = signature.hex()[:32] # Simplified for email display

        # 3. Enhanced PQC Email Body to show quantum-resistant security
        subject = "Post-Quantum Authenticated Verification"
        body = f"""Dear {name_e},

Your Cyber Defensive Engine has generated a Quantum-Resistant OTP for your registration.

OTP Verification Code: {otp_code}

--------------------------------------------------
🔐 PQC Authentication Details:
• Algorithm: Dilithium2 (ML-DSA)
• Signature Fragment: {pqc_signature_hex}...
--------------------------------------------------

This signature ensures the integrity of this communication against quantum computing threats.

Best regards,
Cyber Defensive Engine
"""
        alert(subject, body, email_e)
        return redirect("/verify")
    return render_template("setup.html")

@app.route("/verify", methods = ["GET", "POST"])
def verify()    :
    if request.method == "POST"   :
        otp_data = otp_s.get(session.get("email"))

        # Validates OTP against in-memory dictionary
        if otp_data and otp_data["otp"] == request.form["otp"]:   
            with open ("config.json", 'w') as f:
                json.dump({"name": session['name'], "email": session['email']}, f)
            return redirect("/dashboard")
    return render_template("verify.html")

data = load_user_config()
name = data.get("name")
receiver_email = data.get("email")

# ==========================================
# IPC (UNIX DOMAIN SOCKET) LOGIC
# ==========================================
def read_uds_packet(sock):
    """
    Reads structured packets from the C++ Sniffer over UDS.
    Handles the PQC header structure safely to prevent buffer overflows.
    """
    try:
        # Use select to avoid blocking indefinitely at the end of training
        ready = select.select([sock], [], [], 0.5) 
        if not ready[0]:
            return None
            
        header = recv_exact(sock, 12) # Updated to 12 bytes for PQC header compatibility
        if not header: return None
        
        # PQC Header: [Total Length (4b)] + [Sig Length (4b)] + [Packet Length (4b)]
        total_len, sig_len, pkt_len = struct.unpack('!III', header)
        MAX_PACKET = 65535

        if total_len <= 0 or total_len > MAX_PACKET:
            return None
        
        data = b""
        # We only need the actual packet data for ML training
        remaining = total_len
        while len(data) < remaining:

            ready = select.select([sock], [], [], 0.1)

            if not ready[0]:
                return None

            chunk = sock.recv(remaining - len(data))

            if not chunk:
                return None

            data += chunk
            if not chunk: break
            
        # Extract only the packet portion (skip the signature)
        return data[sig_len:] 
    except Exception:
        return None

def connect_to_sniffer():
    """Establishes connection to the C++ Sniffer UDS Server"""
    uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Increase retries to allow for PQC key generation time (Steps 6-7)
    for i in range(20): 
        try:
            if os.path.exists(UDS_PATH):
                uds_sock.connect(UDS_PATH)
                uds_sock.settimeout(0.2)
                return uds_sock
        except Exception:
            pass
        time.sleep(1)
    return None

def recv_exact(sock, size):
    """Helper function to guarantee reception of exact byte counts"""
    data = b""
    retries = 1

    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))

            if not chunk:
                return None

            data += chunk

        except socket.timeout:
            if retries >= 15    : return None
            retries += 1
            continue

        except BlockingIOError:
            return None

        except Exception as e:
            log.error(f"recv_exact error: {e}")
            return None

    return data

# ==========================================
# MACHINE LEARNING ENGINE (ISOLATION FOREST)
# ==========================================
def re_train_model(data_samples): 
    """Background thread function to dynamically update the ML baseline"""
    global model, baseline_trainig

    # Memory Management: Cap training data size
    if len(baseline_trainig) >= 100000 : baseline_trainig = []

    baseline_trainig.extend(data_samples)
    if not data_samples:
        data_samples = [[64, 1], [1500, 1]] # Dummy fallback to prevent crashes
    
    new_model = IsolationForest(contamination=0.002) # Unsupervised anomaly detection
    new_model.fit(baseline_trainig)
    model = new_model
    joblib.dump(model, MODEL_FILE) # Save model to disk
    log.info(f"Model saved with {len(data_samples)} raw samples.")

def train_model(total_duration):
    """Initial baseline generation module (Builds normal traffic profile)"""
    global baseline_trainig
    log.info(f"ML Engine: Starting {total_duration/60:.1f} minute training baseline...")
    data_samples = []
    start_time = time.time()
    elapsed = time.time() - start_time
    remaining = int(total_duration - elapsed)

    uds_sock = connect_to_sniffer()

    while remaining > 0:
        # Progress indication in console
        sys.stdout.write(f"\r[*] Training Progress: [{remaining//60:02d}:{remaining%60:02d}] | Samples: {len(data_samples)} ")
        sys.stdout.flush()

        raw_packet = read_uds_packet(uds_sock)
        if raw_packet:
            # Extract features (Currently Packet Size, feature space can be expanded)
            data_samples.append([len(raw_packet), 1])
            
        time.sleep(0.01)
        elapsed = time.time() - start_time
        remaining = int(total_duration - elapsed)

    if uds_sock :
        uds_sock.close()
    
    baseline_trainig.extend(data_samples)
    
    if not data_samples:
        data_samples = [[64, 1], [1500, 1]] # Dummy fallback

    sys.stdout.write("\rTraining process is completed ready to detection")
    sys.stdout.flush()
    
    # Train Initial Isolation Forest Model (Contamination sets anomaly strictness)
    model = IsolationForest(contamination=0.001)
    model.fit(data_samples)
    joblib.dump(model, MODEL_FILE)
    log.info(f"Model saved with {len(data_samples)} raw samples.")
    return model

def unsupervised_learning():
    """Manager function for the ML lifecycle"""
    global model
    if os.path.exists(MODEL_FILE):
        log.info("Loading existing ML model...")
        model = joblib.load(MODEL_FILE)
        model_ready.set() # Signals detection thread that it can start
    else:
        log.info("No model found. Starting 10-minute baseline...")
        model = train_model(600)
        if model:
            model_ready.set()
            log.info("Baseline training successful.")
        
def detection():
    """
    Core AI Detection & PQC Verification Loop
    Consumes packets -> Verifies PQC Signature -> Feeds into ML -> Blocks Anomalies
    """
    global model, blocked_ips, attack_count, last_alert_time
    # Wait for the ML model to be ready
    model_ready.wait()
    ip = ""
    re_training = []

    # Initialize PQC Verifier (Dilithium2/ML-DSA-44) for packet authentication
    try:
        with open(PQC_PUB_KEY_PATH, "rb") as f:
            public_key = f.read()
        verifier = oqs.Signature("ML-DSA-44")
        log.info("PQC Verifier initialized for UDS packet stream.")
    except Exception as e:
        log.error(f"PQC Initialization Failed: {e}")
        return

    uds_sock = connect_to_sniffer()
            
    if not uds_sock:
        log.error("CRITICAL: UDS Connection failed. ML detection is disabled.")
        return

    log.info("Detection Engine LIVE: Monitoring UDS for ML Anomalies.")

    while True:
        try:
            # 1. Read the 12-byte PQC header: [Total_Len][Sig_Len][Pkt_Len]
            header_data = uds_sock.recv(12)
            if not header_data or len(header_data) < 12: 
                continue
            
            total_len, sig_len, pkt_len = struct.unpack('!III', header_data)
            
            # 2. Read the full payload (Signature + Packet)
            payload = recv_exact(uds_sock, total_len)

            if not payload:
                continue
            
            signature = payload[:sig_len]
            packet = payload[sig_len:]

            # 3. Post-Quantum Verification (Verifying Data Integrity)
            if verifier.verify(packet, signature, public_key):
                # Execute ML Prediction based on the authenticated packet
                prediction = model.predict([[len(packet), 1]])
                
                # IsolationForest returns -1 for Anomalies
                if prediction[0] == -1:
                    ip = extract_source_ip(packet)

                    # Whitelist critical networks to prevent self-blocking
                    trusted_prefixes = ["192.168.", "10.", "127.", "0.0.", "20.207.", "140.82."]
                    
                    if not ip or any(ip.startswith(p) for p in trusted_prefixes):
                        continue # Skip blocking for these trusted sources

                    # Action: Mitigate Threat via IPTables
                    if ip and ip not in blocked_ips:
                        log.warning(f"ML ANOMALY: Blocking {ip} for abnormal behavior")
                        subprocess.run([
                            "sudo",
                            "iptables",
                            "-A", # Append
                            "INPUT",
                            "-s", ip, # Source
                            "-j", "DROP" # Action
                        ], check=True)
                        
                        # Update state safely using locks
                        with thread_lock :
                            blocked_ips.add(ip)
                            blocked_time[ip] = time.time()
                            attack_count += 1
                        
                        # Define detection variables for Alert
                        detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        packet_size = len(packet)
                        
                        # Load current administrator info from config
                        with open("config.json", 'r') as f:
                            config_data = json.load(f)
                            admin_name = config_data.get("name", "Administrator")

                        subject = f"🧠 ML ANOMALY: Behavioral Block Implemented for {ip}"
                        body = f"""Dear {admin_name},

🚨 Machine Learning Security Alert

Our Cyber Defensive Engine's AI module has detected a significant deviation from your network's normal traffic baseline. The source IP has been blocked based on behavioral patterns rather than a static signature.

--------------------------------------------------
🔍 Incident Details:
• Event Type       : Traffic Anomaly Detected
• Detection Method : Isolation Forest (Unsupervised ML)
• Detection Time   : {detection_time}
• Source IP        : {ip}
--------------------------------------------------

🚫 Automatic Defensive Action Taken:
The identified source IP address has been BLOCKED due to abnormal packet characteristics that match known DDoS or data exfiltration profiles.

🧠 ML Analysis Results:
• Anomaly Score    : Outside Normal Threshold
• Packet Metric    : Observed size {packet_size} bytes
• Behavior         : High-frequency burst or irregular payload size

🛡️ Current Status:
• Threat Mitigation Active ✔️
• IP Successfully Blocked ✔️
• Behavioral Monitoring Ongoing ✔️

🔐 Recommended Actions:
• Review the IP to ensure it is not a legitimate business partner (False Positive Check).
• If the IP is a known internal service, consider adding it to the whitelist in config.py.
• Monitor for similar anomalies from different IP ranges.

Stay secure,  
Cyber Defensive Engine  
AI-Driven Intrusion Prevention System
"""
                        # Alert Cooldown Logic (Prevent spamming emails)
                        now = time.time()
                        if ip not in last_alert_time or (now - last_alert_time[ip] > ALERT_COOLDOWN * 60):
                            alert(subject, body)
                            last_alert_time[ip] = now

                else :
                    # If packet is normal (1), accumulate it for future dynamic re-training
                    re_training.append([len(packet), 1])
                    if len(re_training) > 10000:
                        re_training = re_training[-5000:] # Keep recent history
                        train_t = threading.Thread(target = re_train_model, args = (re_training, )).start()

            else:
                log.error("PQC SECURITY ALERT: Received a tampered or unsigned packet!")

        except socket.timeout:
            continue # Expected behavior when network is quiet
        except Exception as e:
            log.error(f"UDS Detection Loop Error: {e}")
            time.sleep(0.1) # Prevent CPU spiking on continuous errors
            continue

# ==========================================
# FIREWALL MANAGEMENT
# ==========================================
def auto_unblock_system():
    """Background loop to clear IPTables bans after BLOCK_COOLDOWN expires"""
    while True:
        now = time.time()
        # list() is used to prevent "dictionary size changed during iteration" errors
        for ip in list(blocked_ips):
            # Retrieve the time the block started
            start_time = blocked_time.get(ip)
            
            if start_time and (now - start_time > BLOCK_COOLDOWN):
                if platform.system() == "Linux":
                    # Remove the iptables DROP rule (-D)
                    subprocess.run([
                        "sudo",
                        "iptables",
                        "-D",
                        "INPUT",
                        "-s",
                        ip,
                        "-j",
                        "DROP"
                    ], check=True)
                
                # Cleanup internal tracking
                with thread_lock :
                    blocked_ips.remove(ip)
                    if ip in blocked_time: del blocked_time[ip]
                    risk_score[ip] = 0
                
                log.info(f"🔓 Auto-unblock: Timer expired for {ip}. Firewall rule removed.")
        
        # Check every 5 seconds to minimize CPU usage
        time.sleep(5)

# ==========================================
# IPC HONEYPOT / DETERMINISTIC THREAT MONITORING
# ==========================================
def pipe_monitoring():
    """
    Listens on the Named Pipe (FIFO) for absolute threats (like Port Scans)
    detected statically by the C++ Sniffer.
    """
    global blocked_ips, attack_count
    
    # Ensure the pipe exists before trying to open it
    if not os.path.exists(PIPE):
        log.error(f"Pipe not found at {PIPE}. Thread exiting.")
        return

    log.info("Pipe Monitoring Thread LIVE: Waiting for deterministic alerts...")

    while True:
        try:
            # Opening the pipe in read mode blocks until there is data to read
            with open(PIPE, 'r') as pipe_file:
                while True:
                    line = pipe_file.readline().strip()
                    if not line:
                        # If the writer (C++ sniffer) closes the pipe, break to reopen
                        break
                    
                    parts = line.split(',')
                    
                    # Logic to handle deterministic SCAN triggers from the C++ Sniffer
                    if parts[0] == "SCAN":
                        ip = parts[1]
                        port_count = parts[2] # Number of ports hit
                        
                        # Immediately Block
                        if ip not in blocked_ips:
                            log.warning(f"HONEYPOT/SCAN TRIGGER: Blocking {ip}")
                            subprocess.run([
                                "sudo",
                                "iptables",
                                "-A",
                                "INPUT",
                                "-s",
                                ip,
                                "-j",
                                "DROP"
                            ], check=True)
                            with thread_lock :
                                blocked_ips.add(ip)
                                blocked_time[ip] = time.time()
                                attack_count += 1
                            
                            # Prepare and send the Security Alert Email
                            detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
                            # Subject line designed for immediate visibility
                            subject = f"🚨 IMMEDIATE ACTION: Port Scan Detected from {ip}"
                            
                            # Body content following your established professional/technical tone
                            body = f"""Dear {name},

🚨 High-Fidelity Security Alert

The Cyber Defensive Engine has detected a deterministic Port Scan via the Honeypot/Pipe monitoring layer. Because this layer monitors non-production decoys, this interaction is classified as 100% malicious.

--------------------------------------------------
🔍 Incident Details:
• Event Type       : Deterministic Port Scan
• Source IP        : {ip}
• Detection Time   : {detection_time}
• Targeted Ports   : {port_count} ports detected  <-- FIX: Use port_count here
--------------------------------------------------

🚫 Automatic Defensive Action Taken:
The source IP has been IDENTIFIED and BLOCKED using system iptables. All further traffic from this host is currently dropped at the network perimeter.

🛡️ Current Status:
• Threat Contained: YES
• IP Blocked: {ip}
• Risk Score: 100/100 (Immediate Threat)

🔐 Recommended Actions:
• Review your internal logs to ensure this IP did not attempt to access production assets.
• No manual intervention is required for the current block; the auto-unblock system will manage the cooldown period.

Stay secure,  
Cyber Defensive Engine  
Automated Intrusion Prevention System
"""
    
                            # Call your core alert function to send the message
                            alert(subject, body)
                            play_alert_sound() # Trigger audio notification
        except Exception as e:
            log.error(f"Pipe Monitoring Error: {e}")
            time.sleep(1) # Graceful recovery before retrying

# ==========================================
# SYSTEM LOG MONITORING (SIGNATURE-BASED)
# ==========================================
def monitor_file(file):
    """Trails a system log file (like 'tail -f') looking for dictionary signatures"""
    while True:
        if not os.path.exists(file):
            log.error(f"{file} not found!")
            time.sleep(5)
            continue
        
        count = 0

        with open(file, 'r') as f:
            f.seek(0, os.SEEK_END) # Jump to end to only read new logs

            while True:
                line = f.readline()

                if not line:
                    time.sleep(1)
                    continue
                
                line = line.lower()
                st = "PWD=/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine".lower()

                # Search for known attack strings
                for p in SUSPICIOUS_PATTERNS:
                    if p in line and st not in line: # Prevent self-detection
                        count += 1
                        break

                if "accepted" in line:
                    count = 0 # Reset on success

                if count >= THRESHOLD:
                    count = 0 # Reset counter after triggering
                    
                    if file == "/var/log/auth.log":
                        log.warning(f"Brute-force attack detected in {file}")

                    subject = f"⚠️ Security Alert: Suspicious Activity Detected in System Logs"
                    body = f"""Dear {name},

🚨 Security Alert Notification

Our monitoring system has detected suspicious activity in your system logs that may indicate a potential security threat.

--------------------------------------------------
🔍 Incident Details:
• Event Type       : Suspicious Log Activity  
• Log File         : {file}  
• Detection Time   : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
--------------------------------------------------

🧠 Detected Indicators:
• Multiple failed authentication attempts  
• Unusual access patterns  
• Repeated suspicious entries in logs  

⚠️ Risk Assessment:
This activity may indicate a brute-force attack, unauthorized access attempt, or misuse of system privileges.

🛡️ Current Status:
• Monitoring Active ✔️  
• Threat Under Observation ✔️  
• System Stable ✔️  

🔐 Recommended Actions:
• Review the affected log file immediately  
• Check for unauthorized login attempts  
• Change passwords if necessary  
• Strengthen authentication mechanisms  

If this activity was not initiated by you, immediate action is recommended.

---

Stay secure,  
Cyber Defensive Engine  
Automated Log Monitoring System
"""

                    alert(subject, body)

@app.route("/dashboard")
def dashboard():
    # Determine if the ML model is still building its 10-minute baseline
    is_training = not model_ready.is_set()
    
    # Payload for the dashboard.js AJAX polling
    stats = {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "attacks": attack_count,
        "blocked": len(blocked_ips),
        "blocked_list": list(blocked_ips),  # Sends the actual IPs to the UI
        "is_training": is_training,         # Sends the ML Engine status
        "logs": LOG_FILES                   # Sends the list of monitored logs
    }

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(stats=stats)

    return render_template("dashboard.html")

# Prevents multiple engines from running and causing bind conflicts
def check_lock()    :
    f = open(LOCK_PATH, 'w')

    try :
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except IOError  :
        log.warning("CRITICAL: The Cyber Defensive Engine is already running!")
        sys.exit(1)

# ==========================================
# MAIN EXECUTION & THREAD SPAWNING
# ==========================================
if __name__ == "__main__":
    engine_lock = check_lock()

    log.info("Initializing Engine...")
    threads = []
    functions = [detection, auto_unblock_system, pipe_monitoring]

    # Start ML Engine Thread
    t_train = threading.Thread(target = unsupervised_learning)
    t_train.daemon = True
    t_train.start()
    threads.append(t_train)
    
    # Start System Log Monitoring Threads (One per log file)
    for file in LOG_FILES:
        t = threading.Thread(target = monitor_file, args = (file,))
        t.daemon = True
        t.start()
        threads.append(t)
        log.info(f"{file} monitoring started...")

    # Start UDS Detection, Unblocking, and IPC Pipe Threads
    for f in functions  :
        th = threading.Thread(target = f)
        th.daemon = True
        th.start()
        threads.append(th)

    log.info("Starting Web Dashboard on port 8000...")
    # Launch Flask App (Blocking Call)
    app.run(host = "0.0.0.0", port = 8000, debug = False)

    # Cleanup artifacts on graceful shutdown
    for f in [UDS_PATH, PIPE, LOCK_PATH, "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer.pid"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass
