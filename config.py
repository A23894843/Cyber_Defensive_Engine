import os

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/kern.log"
]

SUSPICIOUS_PATTERNS = {"failed"}

THRESHOLD = 3
ALERT_COOLDOWN = 10
TRAIN_DURATION = 30
BLOCK_COOLDOWN = 60
log_path = os.path.join(os.getcwd(), "Cyber_defensive_engine.log")
MODEL_FILE = os.path.join(os.getcwd(), "model.pkl")
PIPE = "/tmp/packet_pipe"
model = None

sender_email = "cyberdefensiveengine@gmail.com"
sender_password = "bafj qcup cbiz hrqz"
receiver_email = "receiver_email"
