import os
import ssl
import time
import joblib
import smtplib
import logging
import subprocess
import threading
import numpy as np
from config import *
from datetime import datetime
from collections import defaultdict
from email.message import EmailMessage
from sklearn.ensemble import IsolationForest

log = logging.getLogger("Cyber_Defensive_Engine")
log.setLevel(logging.INFO)
model_ready = threading.Event()
model_ready_ = False

if not log.handlers:
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

def alert(subject, body):
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = receiver_email
    message.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.send_message(message)
        log.info(f"Email sent to {receiver_email}")
    except Exception as e:
        log.error(f"Failed to send email alert: {e}")

def train_model():
    global model_ready_
    log.info("ML Engine Started....")
    data = []
    start = time.time()

    # Wait for the pipe to be created by the sniffer if it doesn't exist yet
    while not os.path.exists(PIPE):
        time.sleep(1)

    with open(PIPE, 'r') as pipe:
        while time.time() - start < TRAIN_DURATION:
            line = pipe.readline().strip()

            if not line:
                print('Data is not received through Pipe Please check')
                time.sleep(0.5)
                continue

            try:
                ip, pkt, bytes_ = line.split(',')
                pkt = int(pkt)
                bytes_ = int(bytes_)
                data.append([pkt, bytes_])
            except ValueError:
                continue
                
    log.info(f"Collected {len(data)} samples")
    
    model = IsolationForest(contamination=0.01)
    
    if not data:
        log.warning("No data collected during training. Using dummy baseline.")
        data = [[1, 64], [2, 128], [1, 50]] 
        
    model.fit(data)

    joblib.dump(model, MODEL_FILE)
    log.info("Model saved")

    model_ready_ = True
    return model

def unsupervised_learning():
    global model
    if os.path.exists(MODEL_FILE):
        log.info("Loading existing model...")
        model = joblib.load(MODEL_FILE)
    else:
        model = train_model()

def train_model_thread():
    global model
    model = train_model()
    model_ready.set()

def detection():
    log.info("Waiting for model...")
    model_ready.wait()

    log.info("Starting real-time detection...")

    last_alert_time = {}
    last_block_time = {}
    blocked_ips = set()

    with open(PIPE, 'r') as pipe:
        while True:
            line = pipe.readline().strip()

            if not line:
                time.sleep(0.1)
                continue

            try:
                ip, pkt, bytes_ = line.split(",")
                pkt = int(pkt)
                bytes_ = int(bytes_)

                data = np.array([[pkt, bytes_]])
                prediction = model.predict(data)

                if prediction[0] == -1:
                    log.warning(f"Anomaly detected from {ip}")

                    now = time.time()
                    if ip in last_alert_time and now - last_alert_time[ip] < ALERT_COOLDOWN:
                        continue
                    
                    last_alert_time[ip] = now

                    if ip in blocked_ips:
                        continue

                    if ip in last_block_time and now - last_block_time[ip] < BLOCK_COOLDOWN:
                        continue

                    last_block_time[ip] = now

                    log.info(f"Blocking {ip}")

                    # Format the alert
                    subject = f"🚫 Security Action Taken: Blocked {ip} (DDoS Mitigation)"
                    body = f"""Dear User,

🚨 Security Action Notification

Our Cyber Defensive Engine has detected malicious network behavior consistent with a Distributed Denial-of-Service (DDoS) attack and has taken immediate protective action.

--------------------------------------------------
🔍 Incident Details:
• Event Type       : Confirmed Malicious Activity  
• Attack Type      : DDoS (High Traffic Anomaly)  
• Detection Time   : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
• Blocked IP       : {ip}  
--------------------------------------------------

🚫 Automatic Defensive Action Taken:
The identified source IP address has been automatically BLOCKED to prevent further malicious traffic.

🧠 Reason for Blocking:
• Excessive packet rate detected  
• Repeated abnormal connection attempts  
• Traffic deviating from normal baseline  

🛡️ Current Status:
• Threat Contained ✔️  
• IP Successfully Blocked ✔️  
• System Stable ✔️  

🔐 Recommended Actions:
• Review logs for additional suspicious IPs  
• Monitor network activity  
• Keep firewall rules updated  

No immediate action is required from your side.

Stay secure,  
Cyber Defensive Engine  
Automated Intrusion Prevention System
"""
                    alert(subject, body)

                    # Execute iptables block
                    os.system(
                        f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null || "
                        f"sudo iptables -A INPUT -s {ip} -j DROP"
                    )   
                    blocked_ips.add(ip)

            except Exception as e:
                log.error(f"Detection error: {e}")

def monitor_file(file):
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

                for p in SUSPICIOUS_PATTERNS:
                    if p in line:
                        count += 1
                        break

                if "accepted" in line:
                    count = 0

                if count >= THRESHOLD:
                    count = 0
                    
                    if file == "/var/log/auth.log":
                        log.warning(f"Brute-force attack detected in {file}")

                    subject = f"⚠️ Security Alert: Suspicious Activity Detected in System Logs"
                    body = f"""Dear User,

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

#---------Main------------------------
if __name__ == "__main__":
    if os.path.exists(log_path)  :
        os.remove(log_path)
        print(f"Deleted : {log_path}")

    if os.path.exists(os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log"))  :
        os.remove(os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log"))
        print(f"Deleted : {os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log")}")


    if not os.path.exists("./sniffer")    :
        subprocess.run(["g++","sniffer.cpp","-o","sniffer","-lpcap"])

    # Start the C++ sniffer
    try:
        sniffer = subprocess.Popen(["sudo", "./sniffer"])
        time.sleep(2)
    except FileNotFoundError:
        print("Error: ./sniffer executable not found. Did you compile it?")
        exit(1)
    
    threads = []

    for file in LOG_FILES:
        t = threading.Thread(target=monitor_file, args=(file,))
        t.daemon = True
        t.start()
        threads.append(t)
        log.info(f"{file} monitoring started...")

    time.sleep(2)

    t_train = threading.Thread(target=train_model_thread)
    t_train.daemon = True
    t_train.start()
    threads.append(t_train)

    t_detect = threading.Thread(target=detection)
    t_detect.daemon = True
    t_detect.start()
    threads.append(t_detect)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Engine shutting down...")
        sniffer.terminate()
