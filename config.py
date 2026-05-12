import os
import threading
from collections import defaultdict

# ==========================================
# SYSTEM LOG MONITORING CONFIGURATION
# ==========================================
# Defines the critical Linux system logs to monitor for signature-based threats
LOG_FILES = [
    "/var/log/auth.log",    # Monitors sudo, pam_unix, and ssh-agent
    "/var/log/syslog",      # Monitors systemd, polkitd, and lightdm events
    "/var/log/kern.log",    # For kernel-level firewall drops
    "/var/log/dpkg.log",    # Monitors apt update/install activities seen in logs
]

# ==========================================
# THREAT SIGNATURE DATABASE
# ==========================================
# A set of known malicious strings and behaviors used by the file monitoring thread
SUSPICIOUS_PATTERNS = {
    # --- Authentication & Access ---
    "password check failed",       # Confirmed in log: "password check failed for user"
    "authentication failure",      # Confirmed in log: "authentication failure; logname=abhinandan-kali"
    "incorrect password attempts", 
    "conversation failed",         # Confirmed in log: "pam_unix(sudo:auth): conversation failed"
    "auth could not identify",     # Confirmed in log: "auth could not identify password"
    "permission denied",           
    "setuid failed",               # Confirmed in log: "setuid failed: Operation not permitted"

    # --- Privilege Escalation & System Tools ---
    # "pkexec",                    # REMOVED: Triggers false positives on screen brightness changes (xfpm-power-backlight-helper)
    "operator ... authenticated",  
    "unregistered authentication", 
    "executing command [user=root]", 

    # --- Network & Tools (Based on your activity) ---
    "iptables -a input",           # Detects manual firewall modifications
    "killall -9 sniffer",          # UPDATED: Matches the actual termination command found in auth.log
    "rm /tmp/packet_pipe",         # Detects unauthorized deletion of your data pipe
    "promiscuous mode",            # Standard sniffer detection
    
    # --- Web & Application Attacks ---
    # Common payload signatures for SQL injection, XSS, and Directory Traversal
    "union select",
    "1=1",
    "<script>",
    "../",
    "/etc/passwd"
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

# Real-time tracking dictionaries
last_alert_time = {}   # Tracks when an IP last triggered an email alert
risk_score = defaultdict(int)
failed_attempts = defaultdict(int)
baseline_trainig = []  # Accumulates packet data for ML retraining
attack_count = 0       # Global counter for dashboard statistics
alert_history = []     # History of alerts generated

# ==========================================
# FILE PATH DEFINITIONS
# ==========================================
# Absolute paths for IPC, Logs, Models, and Keys
log_path = os.path.join(BASE_DIR +  "/Cyber_Defensive_Engine.log")
MODEL_FILE = os.path.join(BASE_DIR +  "/model.pkl") # Serialized scikit-learn model
PIPE = os.path.join(BASE_DIR + "/packet_pipe")      # Named Pipe (FIFO) for deterministic alerts
UDS_PATH = os.path.join(BASE_DIR + "/Cyber_Defensive_Engine.sock") # Unix Domain Socket for ML data
PQC_PUB_KEY_PATH = os.path.join(BASE_DIR + "/pqc_public_key.bin")  # Exported Dilithium Public Key
LOCK_PATH = os.path.join(BASE_DIR + "/main_engine.pid") # Prevents multiple engine instances
LOGO = os.path.join(BASE_DIR + "/logo.png")

# Runtime variables
model = None           # Holds the active IsolationForest instance
blocked_ips = set()    # In-memory firewall tracking
blocked_time = {}      # Timestamps for auto-unblock logic
engine_status = "STABLE"

# ==========================================
# NOTIFICATION & ALERTING CREDENTIALS
# ==========================================
sender_email = "your_gmail_id"
sender_password = "your_gmail_app_paddword" # App-specific password for SMTP authentication
name = None
receiver_email = None

# Threading event to synchronize detection loop with ML model readiness
model_ready = threading.Event()
