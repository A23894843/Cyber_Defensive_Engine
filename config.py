import os

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/kern.log"
]

SUSPICIOUS_PATTERNS = {"failed"}

THRESHOLD = 3
TRAIN_DURATION = 30
BLOCK_COOLDOWN = 60
log_path  = os.path.expanduser("~/Cyber_defensive_engine.log")
MODEL_FILE = os.path.expanduser("~/model.pkl")
PIPE = "/tmp/packet_pipe"
model = None

sender_email = "cyberdefensiveengine@gmail.com"
sender_password = "   "
receiver_email = "a23894843@gmail.com"
