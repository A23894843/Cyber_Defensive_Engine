import os
import threading
from collections import defaultdict

LOG_FILES = [
    "/var/log/auth.log",    # Monitors sudo, pam_unix, and ssh-agent
    "/var/log/syslog",      # Monitors systemd, polkitd, and lightdm events
    "/var/log/kern.log",    # For kernel-level firewall drops
    "/var/log/dpkg.log",    # Monitors apt update/install activities seen in logs
]

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
    "union select",
    "1=1",
    "<script>",
    "../",
    "/etc/passwd"
}

BASE_DIR = os.getcwd()
otp_s = {}
THRESHOLD = 3
ALERT_COOLDOWN = 10
TRAIN_DURATION = 600
BLOCK_COOLDOWN = 300
last_alert_time = {}
risk_score = defaultdict(int)
failed_attempts = defaultdict(int)
baseline_trainig = []
attack_count = 0
alert_history = []
log_path = os.path.join(BASE_DIR +  "/Cyber_Defensive_Engine.log")
MODEL_FILE = os.path.join(BASE_DIR +  "/model.pkl")
PIPE = os.path.join(BASE_DIR + "/packet_pipe")
UDS_PATH = os.path.join(BASE_DIR + "/Cyber_Defensive_Engine.sock")
PQC_PUB_KEY_PATH = os.path.join(BASE_DIR + "/pqc_public_key.bin")
LOCK_PATH = os.path.join(BASE_DIR + "/main_engine.pid")
model = None
blocked_ips = set()
LOGO = os.path.join(BASE_DIR + "/logo.png")
blocked_time = {}
engine_status = "STABLE"

sender_email = "cyberdefensiveengine@gmail.com"
sender_password = "evtc fvce saiv vzur"
name = None
receiver_email = None

model_ready = threading.Event()
