"""
Cyber Defensive Engine - Main Controller
Orchestrates the Flask Dashboard, Machine Learning (Isolation Forest), 
Post-Quantum Cryptography (ML-DSA-44), SQLite Database, and Subsystem threads.
"""
import os
import oqs
import ssl
import sys
import time
import fcntl
import socket
import struct
import select
import psutil
import joblib
import sqlite3
import smtplib
import logging
import platform
import subprocess
import threading
import numpy as np
from config import *
import random as ran
from functools import wraps
from datetime import datetime
from flask_mail import Mail, Message
from email.message import EmailMessage
from sklearn.ensemble import IsolationForest
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, session, jsonify

if platform.system() == "Windows":
    import winsound

# ==========================================
# SYSTEM & DATABASE INITIALIZATION
# ==========================================
is_valid = True

# IPC Setup: Ensure Named Pipe exists for Deterministic Threat alerts
if not os.path.exists(PIPE):
    subprocess.run(["mkfifo", PIPE])
    subprocess.run(["chmod", "777", PIPE])

time.sleep(2)

thread_lock = threading.Lock() # Mutex for safe multi-threading

# Flask UI Initialization
app = Flask(__name__)
app.secret_key = os.urandom(32) # Cryptographically secure session key

# Suppress standard Flask request logging to keep console clean
log_werkzeug = logging.getLogger('werkzeug')
log_werkzeug.setLevel(logging.ERROR)

def init_db():
    """
    Initializes the SQLite Database. 
    Creates tables for secure Administrator Login and persistent Attack History.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Administrator credentials table (passwords are hashed, never plaintext)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Forensic log table for dashboard reporting
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            ip_address TEXT,
            event_type TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db() # Execute DB setup on boot

if os.path.exists(log_path):  
    os.remove(log_path) # Clear old session logs

# Compile C++ Sniffer automatically if missing
if not os.path.exists("./sniffer"):
    subprocess.run(["g++", "-o", "sniffer", "sniffer.cpp", "-lpcap", "-loqs", "-lcrypto", "-O3"])
    time.sleep(3)

# Configure primary Engine Logger
log = logging.getLogger("Cyber_Defensive_Engine")
log.setLevel(logging.INFO)

if not log.handlers:
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

# Configure SMTP settings for Email Alerts
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USERNAME = sender_email,
    MAIL_PASSWORD = sender_password
)
mail = Mail(app)

# Launch C++ Network Sniffer Subprocess (Requires Root)
try:
    sniffer = subprocess.Popen(["sudo", "./sniffer"])
    time.sleep(2)
except FileNotFoundError:
    log.warning("Error: ./sniffer executable not found. Did you compile it?")
    exit(1)

if sniffer.poll() is not None:
    log.error("Sniffer process crashed!")
    sys.exit(1)

# ==========================================
# DATABASE ABSTRACTION & HELPER LOGIC
# ==========================================
def load_user_config():
    """Fetches administrator details safely from SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name, email, password_hash FROM users LIMIT 1")
        user = cursor.fetchone()
        conn.close()
        if user:
            return {"name": user[0], "email": user[1], "password": user[2]}
    except Exception as e:
        log.error(f"DB Load Error: {e}")
    return {}

def log_attack_to_db(ip, event_type, description):
    """Inserts a confirmed threat event into the SQLite history log."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_history (timestamp, ip_address, event_type, description) 
            VALUES (?, ?, ?, ?)
        ''', (timestamp, ip, event_type, description))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Failed to log attack to DB: {e}")

data = load_user_config()
name = data.get("name")
receiver_email = data.get("email")

# Platform-agnostic audible alert
def play_alert_sound():
    if platform.system() == "Windows":
        threading.Thread(target=lambda: winsound.Beep(1000, 500), daemon=True).start()
    else:
        print('\a')

def alert(subject, body, email=receiver_email):
    """Dispatches asynchronous email alerts over TLS."""
    if not email: return
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

def extract_source_ip(raw_packet):
    """Parses raw packet bytes to extract the IPv4 Source Address."""
    try:
        ip_header = raw_packet[14:34]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        return src_ip
    except:
        return None

# Auth Decorator: Protects dashboard routes from unauthorized access
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# FLASK WEB ROUTES (UI Controllers)
# ==========================================
@app.route("/")
def home():
    """Initial routing logic based on setup and session status."""
    current_config = load_user_config()
    if not current_config.get("name") or not current_config.get("email"):
        return redirect("/setup")
    if not session.get('logged_in'):
        return redirect("/login")
    return redirect("/dashboard")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Handles initial system configuration and generates PQC-signed OTP."""
    global otp_s
    if request.method == "POST":
        name_e = request.form["name"]
        email_e = request.form["email"]
        password_e = request.form["password"]

        session["name"] = name_e
        session["email"] = email_e
        session["password"] = generate_password_hash(password_e)

        # Generate standard 6-digit OTP
        otp_code = str(ran.randint(100000, 999999))
        otp_s[email_e] = {"otp": otp_code, "time": time.time()}

        # Generate Post-Quantum Signature using Liboqs ML-DSA-44
        try:
            with open("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer_private_key.bin", "rb") as f:
                sk = f.read()
            
            sig_instance = oqs.Signature("ML-DSA-44", secret_key=sk)
            signature = sig_instance.sign(otp_code.encode())
            pqc_signature_hex = signature.hex()[:32] 
        except Exception as e:
            log.error(f"Failed to load PQC Private key, using fallback signature block: {e}")
            pqc_signature_hex = "ERROR_LOADING_KEY_FALLBACK"

        subject = "Post-Quantum Authenticated Verification"
        body = f"""Dear {name_e},\n\nYour Cyber Defensive Engine has generated a Quantum-Resistant OTP for your registration.\n\nOTP Verification Code: {otp_code}\n\n--------------------------------------------------\n🔐 PQC Authentication Details:\n• Algorithm: Dilithium2 (ML-DSA)\n• Signature Fragment: {pqc_signature_hex}...\n--------------------------------------------------\n\nThis signature ensures the integrity of this communication against quantum computing threats.\n\nBest regards,\nCyber Defensive Engine"""
        alert(subject, body, email_e)
        return redirect("/verify")
    return render_template("setup.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    """Validates the OTP and permanently saves the Admin profile to SQLite."""
    if request.method == "POST":
        otp_data = otp_s.get(session.get("email"))

        if otp_data and otp_data["otp"] == request.form["otp"]:   
            # Store validated admin credentials into SQLite
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users") # Overwrite previous admins
            cursor.execute('''
                INSERT INTO users (name, email, password_hash) 
                VALUES (?, ?, ?)
            ''', (session['name'], session['email'], session['password']))
            conn.commit()
            conn.close()
            
            session['logged_in'] = True
            return redirect("/dashboard")
    return render_template("verify.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles secure returning administrator logins using hashed passwords."""
    config = load_user_config()
    if not config.get("name"):
        return redirect("/setup")

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Verify hashed password
        if email == config.get("email") and check_password_hash(config.get("password", ""), password):
            session['logged_in'] = True
            return redirect("/dashboard")
        else:
            # Log failed login attempts to the attack history database
            log_attack_to_db(request.remote_addr, "DASHBOARD INTRUSION", "Failed administrator login attempt.")
            return render_template("login.html", error="Invalid credentials. Intrusion logged.")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Terminates the secure session."""
    session.pop('logged_in', None)
    return redirect("/login")

@app.route("/dashboard")
@login_required # Gatekeeper: Prevents unauthorized viewing
def dashboard():
    """Renders the main UI and serves AJAX polling requests."""
    is_training = not model_ready.is_set()
    
    # Fetch recent attack history from SQLite to display on the dashboard
    history = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, ip_address, event_type, description FROM attack_history ORDER BY id DESC LIMIT 15")
        for row in cursor.fetchall():
            history.append({
                "timestamp": row[0],
                "ip": row[1],
                "type": row[2],
                "desc": row[3]
            })
        conn.close()
    except Exception as e:
        log.error(f"Failed to fetch DB history: {e}")

    # Telemetry Payload for Frontend
    stats = {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "attacks": attack_count,
        "blocked": len(blocked_ips),
        "blocked_list": list(blocked_ips),
        "is_training": is_training,         
        "logs": LOG_FILES,
        "attack_history": history # Injects database rows into JSON
    }

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(stats=stats)

    return render_template("dashboard.html")

# ==========================================
# IPC (UNIX DOMAIN SOCKET) LOGIC
# ==========================================
def read_uds_packet(sock):
    """Safely reads PQC-signed packets from the C++ process over UDS."""
    try:
        ready = select.select([sock], [], [], 0.5) 
        if not ready[0]: return None
            
        header = recv_exact(sock, 12) 
        if not header: return None
        
        # Unpack custom header: Total Length | Sig Length | Packet Length
        total_len, sig_len, pkt_len = struct.unpack('!III', header)
        MAX_PACKET = 65535

        if total_len <= 0 or total_len > MAX_PACKET: return None
        
        data = b""
        remaining = total_len
        while len(data) < remaining:
            ready = select.select([sock], [], [], 0.1)
            if not ready[0]: return None
            chunk = sock.recv(remaining - len(data))
            if not chunk: return None
            data += chunk
            if not chunk: break
            
        return data[sig_len:] # Return only the raw packet (strip signature)
    except Exception:
        return None

def connect_to_sniffer():
    uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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
    data = b""
    retries = 1
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
            if not chunk: return None
            data += chunk
        except socket.timeout:
            if retries >= 15: return None
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
    """Dynamically re-trains the model to prevent data drift over time."""
    global model, baseline_training
    if len(baseline_training) >= 100000 : baseline_training = []
    baseline_training.extend(data_samples)
    if not data_samples: data_samples = [[64, 1], [1500, 1]] 
    
    new_model = IsolationForest(contamination=0.002)
    new_model.fit(baseline_training)
    model = new_model
    joblib.dump(model, MODEL_FILE)
    log.info(f"Model saved with {len(data_samples)} raw samples.")

def train_model(total_duration):
    """Generates the initial behavioral baseline of network traffic."""
    global baseline_training
    log.info(f"ML Engine: Starting {total_duration/60:.1f} minute training baseline...")
    data_samples = []
    start_time = time.time()
    elapsed = time.time() - start_time
    remaining = int(total_duration - elapsed)

    uds_sock = connect_to_sniffer()

    while remaining > 0:
        sys.stdout.write(f"\r[*] Training Progress: [{remaining//60:02d}:{remaining%60:02d}] | Samples: {len(data_samples)} ")
        sys.stdout.flush()

        raw_packet = read_uds_packet(uds_sock)
        if raw_packet:
            data_samples.append([len(raw_packet), 1]) # Extract Packet Length feature
            
        time.sleep(0.01)
        elapsed = time.time() - start_time
        remaining = int(total_duration - elapsed)

    if uds_sock : uds_sock.close()
    baseline_training.extend(data_samples)
    if not data_samples: data_samples = [[64, 1], [1500, 1]] 

    sys.stdout.write("\rTraining process is completed ready to detection")
    sys.stdout.flush()
    
    model = IsolationForest(contamination=0.001)
    model.fit(data_samples)
    joblib.dump(model, MODEL_FILE)
    log.info(f"Model saved with {len(data_samples)} raw samples.")
    return model

def unsupervised_learning():
    """Thread manager for ML model lifecycle."""
    global model
    if os.path.exists(MODEL_FILE):
        log.info("Loading existing ML model...")
        model = joblib.load(MODEL_FILE)
        model_ready.set()
    else:
        log.info("No model found. Starting 10-minute baseline...")
        model = train_model(600)
        if model:
            model_ready.set()
            log.info("Baseline training successful.")
        
def detection():
    """
    Core AI Detection & PQC Verification Loop.
    Authenticates IPC streams using Post-Quantum Crypto before feeding to ML.
    """
    global model, blocked_ips, attack_count, last_alert_time
    model_ready.wait()
    ip = ""
    re_training = []

    # Initialize Liboqs ML-DSA-44 Verifier
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
            header_data = uds_sock.recv(12)
            if not header_data or len(header_data) < 12: continue
            
            total_len, sig_len, pkt_len = struct.unpack('!III', header_data)
            payload = recv_exact(uds_sock, total_len)

            if not payload: continue
            signature = payload[:sig_len]
            packet = payload[sig_len:]

            # Post-Quantum Verification Check
            if verifier.verify(packet, signature, public_key):
                prediction = model.predict([[len(packet), 1]])
                
                # If Anomaly (-1) Detected
                if prediction[0] == -1:
                    ip = extract_source_ip(packet)
                    trusted_prefixes = ["192.168.", "10.", "127.", "0.0.", "20.207.", "140.82."]
                    
                    if not ip or any(ip.startswith(p) for p in trusted_prefixes):
                        continue 

                    # Execute Mitigation (Firewall Drop)
                    if ip and ip not in blocked_ips:
                        log.warning(f"ML ANOMALY: Blocking {ip} for abnormal behavior")
                        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                        
                        with thread_lock :
                            blocked_ips.add(ip)
                            blocked_time[ip] = time.time()
                            attack_count += 1
                        
                        # Store in SQLite History
                        packet_size = len(packet)
                        log_attack_to_db(ip, "ML ANOMALY", f"Blocked due to abnormal packet behavior (Size: {packet_size} bytes)")
                        
                        detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                        config = load_user_config()
                        admin_name = config.get("name", "Administrator")

                        subject = f"🧠 ML ANOMALY: Behavioral Block Implemented for {ip}"
                        body = f"Dear {admin_name},\n\n🚨 Machine Learning Security Alert\n\nOur Cyber Defensive Engine's AI module has detected a significant deviation from your network's normal traffic baseline. The source IP has been blocked based on behavioral patterns rather than a static signature.\n\n--------------------------------------------------\n🔍 Incident Details:\n• Event Type       : Traffic Anomaly Detected\n• Detection Method : Isolation Forest (Unsupervised ML)\n• Detection Time   : {detection_time}\n• Source IP        : {ip}\n--------------------------------------------------\n\nStay secure,  \nCyber Defensive Engine"

                        # Send Email Alert (w/ Cooldown)
                        now = time.time()
                        if ip not in last_alert_time or (now - last_alert_time[ip] > ALERT_COOLDOWN * 60):
                            alert(subject, body, config.get("email"))
                            last_alert_time[ip] = now

                else :
                    # Keep valid packets for drift retraining
                    re_training.append([len(packet), 1])
                    if len(re_training) > 10000:
                        re_training = re_training[-5000:]
                        threading.Thread(target = re_train_model, args = (re_training, )).start()

            else:
                log.error("PQC SECURITY ALERT: Received a tampered or unsigned packet!")

        except socket.timeout: continue
        except Exception as e:
            log.error(f"UDS Detection Loop Error: {e}")
            time.sleep(0.1) 
            continue

# ==========================================
# FIREWALL MANAGEMENT & HONEYPOTS
# ==========================================
def auto_unblock_system():
    """Removes iptables drops automatically after BLOCK_COOLDOWN expires."""
    while True:
        now = time.time()
        for ip in list(blocked_ips):
            start_time = blocked_time.get(ip)
            if start_time and (now - start_time > BLOCK_COOLDOWN):
                if platform.system() == "Linux":
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                
                with thread_lock :
                    blocked_ips.remove(ip)
                    if ip in blocked_time: del blocked_time[ip]
                    risk_score[ip] = 0
                
                # Log the Unblock action to DB
                log_attack_to_db(ip, "FIREWALL UNBLOCK", "Timer expired. Firewall drop rule removed.")
                log.info(f"🔓 Auto-unblock: Timer expired for {ip}. Firewall rule removed.")
        time.sleep(5)

def pipe_monitoring():
    """Listens to the Named Pipe for deterministic threat triggers from C++."""
    global blocked_ips, attack_count
    if not os.path.exists(PIPE):
        log.error(f"Pipe not found at {PIPE}. Thread exiting.")
        return

    log.info("Pipe Monitoring Thread LIVE: Waiting for deterministic alerts...")

    while True:
        try:
            with open(PIPE, 'r') as pipe_file:
                while True:
                    line = pipe_file.readline().strip()
                    if not line: break
                    
                    parts = line.split(',')
                    if parts[0] == "SCAN": # Port Scan Trigger
                        ip = parts[1]
                        port_count = parts[2] 
                        
                        if ip not in blocked_ips:
                            log.warning(f"HONEYPOT/SCAN TRIGGER: Blocking {ip}")
                            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                            with thread_lock :
                                blocked_ips.add(ip)
                                blocked_time[ip] = time.time()
                                attack_count += 1
                            
                            # Store in DB
                            log_attack_to_db(ip, "PORT SCAN", f"Deterministic scan detected hitting {port_count} ports rapidly.")
                            
                            detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            subject = f"🚨 IMMEDIATE ACTION: Port Scan Detected from {ip}"
                            body = f"Dear Administrator,\n\n🚨 High-Fidelity Security Alert\n\nThe Cyber Defensive Engine has detected a deterministic Port Scan via the Honeypot/Pipe monitoring layer. Because this layer monitors non-production decoys, this interaction is classified as 100% malicious.\n\n--------------------------------------------------\n🔍 Incident Details:\n• Event Type       : Deterministic Port Scan\n• Source IP        : {ip}\n• Detection Time   : {detection_time}\n• Targeted Ports   : {port_count} ports detected\n--------------------------------------------------\n\nStay secure,  \nCyber Defensive Engine"
                            alert(subject, body, load_user_config().get("email"))
                            play_alert_sound() 
        except Exception as e:
            log.error(f"Pipe Monitoring Error: {e}")
            time.sleep(1) 

def monitor_file(file):
    """Tails local system log files looking for known malicious signatures."""
    while True:
        if not os.path.exists(file):
            log.error(f"{file} not found!")
            time.sleep(5)
            continue
        
        count = 0
        with open(file, 'r') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                line = line.lower()
                st = "PWD=/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine".lower()

                for p in SUSPICIOUS_PATTERNS:
                    if p in line and st not in line:
                        count += 1
                        break

                if "accepted" in line: count = 0

                if count >= THRESHOLD:
                    count = 0
                    if file == "/var/log/auth.log": log.warning(f"Brute-force attack detected in {file}")

                    # Store in DB
                    log_attack_to_db("Localhost", "LOG ANOMALY", f"Suspicious activity detected in system log: {file}")

                    subject = f"⚠️ Security Alert: Suspicious Activity Detected in System Logs"
                    body = f"Dear Administrator,\n\n🚨 Security Alert Notification\n\nOur monitoring system has detected suspicious activity in your system logs that may indicate a potential security threat.\n\n--------------------------------------------------\n🔍 Incident Details:\n• Event Type       : Suspicious Log Activity  \n• Log File         : {file}  \n• Detection Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n--------------------------------------------------\n\n🧠 Detected Indicators:\n• Multiple failed authentication attempts  \n• Unusual access patterns  \n• Repeated suspicious entries in logs  \n\nStay secure,  \nCyber Defensive Engine"
                    alert(subject, body, load_user_config().get("email"))

# ==========================================
# MAIN EXECUTION THREAD
# ==========================================
def check_lock():
    """Prevents duplicate execution of the engine daemon."""
    f = open(LOCK_PATH, 'w')
    try :
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except IOError  :
        log.warning("CRITICAL: The Cyber Defensive Engine is already running!")
        sys.exit(1)

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
    
    # Start File Monitoring Threads (1 per log file)
    for file in LOG_FILES:
        t = threading.Thread(target = monitor_file, args = (file,))
        t.daemon = True
        t.start()
        threads.append(t)
        log.info(f"{file} monitoring started...")

    # Start Core Functions
    for f in functions:
        th = threading.Thread(target = f)
        th.daemon = True
        th.start()
        threads.append(th)

    log.info("Starting Web Dashboard on port 8000...")
    app.run(host = "0.0.0.0", port = 8000, debug = False)

    # Cleanup artifacts on graceful exit
    for f in [UDS_PATH, PIPE, LOCK_PATH, "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer.pid"]:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass
