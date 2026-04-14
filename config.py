import os
import logging
import threading

LOG_FILES = [
    # Core System & Authentication
    "/var/log/auth.log",       # SSH, sudo, and authentication attempts
    "/var/log/kern.log",       # Kernel logs (hardware, iptables drops, network interfaces)
    "/var/log/syslog",         # General system daemon activity
    
    # Software & Package Management
    "/var/log/dpkg.log",       # Package installations (detects unauthorized tool installations)
    
    # Web Server (Uncomment if you are running Apache or Nginx)
    # "/var/log/apache2/access.log",
    # "/var/log/apache2/error.log",
    # "/var/log/nginx/access.log",
]

SUSPICIOUS_PATTERNS = {
    # --- Authentication & Access (Brute Force) ---
    "failed password",
    "invalid user",
    "authentication failure",
    "connection closed by authenticating user",
    "maximum authentication attempts exceeded",
    "session opened for user root", # Not always an attack, but highly critical to log

    # --- Privilege Escalation ---
    "incorrect password attempt",
    "sudo: auth",
    "not in the sudoers file",

    # --- Network, Kernel & Firewall ---
    "promiscuous mode",  # Alerts if another network sniffer is started
    "segfault",          # Often indicates a buffer overflow attempt crashing a service
    "drop",              # Standard keyword for iptables/UFW blocked packets
    "denied",            # General permission denials
    "port unreach",      # ICMP port unreachable (often happens during UDP scanning)

    # --- Web & Application Attacks (SQLi, XSS, LFI) ---
    # Note: These are particularly useful if monitoring web access logs
    "union select",      # SQL Injection
    "1=1",               # SQL Injection
    "<script>",          # Cross-Site Scripting (XSS)
    "../",               # Directory Traversal
    "/etc/passwd",       # Local File Inclusion (LFI) attempt
    "nmap",              # Often left in the User-Agent string during scanning
    "nikto"              # Web vulnerability scanner signature
}

THRESHOLD = 3
ALERT_COOLDOWN = 10
TRAIN_DURATION = 30
BLOCK_COOLDOWN = 60
log_path = os.path.join(os.getcwd(), "Cyber_defensive_engine.log")
MODEL_FILE = os.path.join(os.getcwd(), "model.pkl")
PIPE = "/tmp/packet_pipe"
model = None

sender_email = "cyberdefensiveengine@gmail.com"
sender_password = os.getenv("EMAIL_PASS")
name = None
receiver_email = None

log = logging.getLogger("Cyber_Defensive_Engine")
log.setLevel(logging.INFO)
model_ready = threading.Event()
model_ready_ = False
