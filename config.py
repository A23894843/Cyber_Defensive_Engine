"""
Cyber Defensive Engine - Configuration Module
Defines global constants, paths, threat signatures, and system variables.
"""
import os
import threading
from collections import defaultdict

# ==========================================
# SYSTEM LOG MONITORING CONFIGURATION
# ==========================================
# Defines the critical Linux system logs to monitor for signature-based threats
LOG_FILES = [
    "/var/log/auth.log",    # Monitors sudo, pam_unix, and ssh-agent (Auth bypass)
    "/var/log/syslog",      # Monitors systemd, polkitd, and lightdm events
    "/var/log/kern.log",    # Monitors kernel-level iptables firewall drops
    "/var/log/dpkg.log",    # Monitors apt update/install activities
]

# ==========================================
# THREAT SIGNATURE DATABASE
# ==========================================
# Known malicious strings used by the file monitoring thread (Signature Detection)
SUSPICIOUS_PATTERNS = {
    # --- Authentication & Access ---
    "password check failed",       
    "authentication failure",      
    "incorrect password attempts", 
    "conversation failed",         
    "auth could not identify",     
    "permission denied",           
    "setuid failed",               

    # --- Privilege Escalation & System Tools ---
    "operator ... authenticated",  
    "unregistered authentication", 
    "executing command [user=root]", 

    # --- Network & Tools (Behavioral Triggers) ---
    "iptables -a input",           # Detects manual firewall modifications
    "killall -9 sniffer",          # Detects attempts to kill the C++ daemon
    "rm /tmp/packet_pipe",         # Detects unauthorized deletion of the IPC pipe
    "promiscuous mode",            # Detects unauthorized packet sniffing
    
    # --- Web & Application Attacks (L7 Payloads) ---
    "union select",                # SQL Injection
    "1=1",                         # SQL Injection bypass
    "<script>",                    # Cross-Site Scripting (XSS)
    "../",                         # Directory Traversal
    "/etc/passwd"                  # Sensitive file access attempt
}

# ==========================================
# GLOBAL STATE & CONSTANTS
# ==========================================
BASE_DIR = os.getcwd() # Dynamically binds to the current working directory
otp_s = {}             # In-memory store for OTP generation and validation
THRESHOLD = 3          # Number of suspicious log entries before triggering an alert
ALERT_COOLDOWN = 10    # Minutes to wait before re-alerting on the same IP
TRAIN_DURATION = 600   # 10 minutes (600s) duration for ML baseline training
BLOCK_COOLDOWN = 300   # 5 minutes (300s) duration before automatically unblocking an IP

# Real-time tracking dictionaries (Thread-safe via locks in main.py)
last_alert_time = {}   
risk_score = defaultdict(int)
failed_attempts = defaultdict(int)
baseline_training = [] # Fixed typo from 'baseline_trainig'
attack_count = 0       
alert_history = []     

# ==========================================
# SYSTEM & DATABASE PATHS
# ==========================================
log_path = os.path.join(BASE_DIR, "Cyber_Defensive_Engine.log")
MODEL_FILE = os.path.join(BASE_DIR, "model.pkl")      # Serialized scikit-learn model
PIPE = os.path.join(BASE_DIR, "packet_pipe")          # Named Pipe (FIFO) for IPC
UDS_PATH = os.path.join(BASE_DIR, "Cyber_Defensive_Engine.sock") # Unix Domain Socket
PQC_PUB_KEY_PATH = os.path.join(BASE_DIR, "pqc_public_key.bin")  # Post-Quantum Public Key
LOCK_PATH = os.path.join(BASE_DIR, "main_engine.pid") # Prevents duplicate execution
LOGO = os.path.join(BASE_DIR, "logo.png")

# SQLite Database for persistent credential and attack history storage
DB_PATH = os.path.join(BASE_DIR, "cde_database.db")

# In-memory tracking for active blocks
model = None           
blocked_ips = set()    
blocked_time = {}      
engine_status = "STABLE"

# ==========================================
# ALERT CREDENTIALS
# ==========================================
sender_email = "cyberdefensiveengine@gmail.com"
sender_password = "evtc fvce saiv vzur" # App-specific password for SMTP
name = None
receiver_email = None

# Thread synchronization event for Machine Learning initialization
model_ready = threading.Event()
