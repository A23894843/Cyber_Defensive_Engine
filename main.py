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

sniffer = subprocess.Popen(["./sniffer"])
time.sleep(2)
log = logging.getLogger("Cyber_Defensive_Engine")
log.setLevel(logging.INFO)

if not log.handlers :
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    log.addHandler(handler)

def alert(msg)  :
    context = ssl.create_default_context()
    with smtplib.SMTP("smtp.gmail.com", 587) as server  :
        server.starttls(context = context)
        server.login(sender_email, sender_password)
        server.send_message(msg)
    log.info(f"Email sent to {receiver_email}")

def train_model() :
    log.info("ML Engine Started....")
    data = []
    start = time.time()

    with open(PIPE,'r') as pipe :
        while time.time() - start < TRAIN_DURATION   :
            line = pipe.readline().strip()

            if not line :
                continue

            try :
                ip, pkt, bytes_ = line.split(',')
                pkt = int(pkt)
                bytes_ = int(bytes_)
                data.append([pkt, bytes_])

            except  :
                continue
    log.info(f" Collected {len(data)} samples")
    
    model = IsolationForest(contamination = 0.05)
    model.fit(data)

    joblib.dump(model, MODEL_FILE)
    log.info("Model saved")

    return model

def unsupervised_learning() :
    global model
    if os.path.exists(MODEL_FILE)  :
        log.info("Loading existing model...")
        model = joblib.load(MODEL_FILE)
    else    :
        model = train_model()

def detection() :
    last_block_time = {}
    log.info("Starting real-time detection...")

    with open(PIPE, 'r') as pipe    :
        while True  :
            line = pipe.readline().strip()

            if not line :
                continue

            try :
                ip, pkt, bytes_ = line.split(",")
                pkt = int(pkt)
                bytes_ = int(bytes_)

                data = np.array([[pkt, bytes_]])
                prediction = model.predict(data)

                if prediction[0] == -1  :
                    log.warning(f"Anomaly detected from {ip}")

                    subject = "⚠️ Security Alert: Anomalous Traffic Detected (Potential DDoS Activity)"

                    body = f"""Dear User,

🚨 Security Alert Notification

Our monitoring system has detected anomalous network activity that may indicate the early stages of a Distributed Denial-of-Service (DDoS) attack on your system.

🔍 Incident Summary:

Event Type: Network Anomaly
Detection Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Anomaly Indicators:
• Unusual spike in incoming traffic
• Abnormal request patterns
• Deviation from normal baseline behavior

⚠️ What This Means:
While this activity has not yet been confirmed as a full-scale attack, it closely resembles patterns commonly associated with DDoS attempts.

🛡️ Recommended Actions:

Monitor system performance and traffic trends
Review logs for repeated or suspicious IP activity
Ensure firewall and rate-limiting rules are active
Stay alert for further notifications

🔐 Our system will continue to monitor this activity in real time and will automatically take defensive actions if the threat escalates.

Stay secure,
Cyber Defensive Engine
Automated Security Monitoring System
"""

                    message = EmailMessage()
                    message['Subject'] = subject
                    message['From'] = sender_email
                    message['To'] = receiver_email
                    message.set_content(body)

                    alert(message)

                    now = time.time()

                    if ip in last_block_time and now - last_block_time[ip] < BLOCK_COOLDOWN :
                        continue
                    
                    last_block_time[ip] = now

                    log.info(f"Blocking {ip}")

                    subject = "🚫 Security Action Taken: Malicious IP Blocked (DDoS Mitigation)"

                    body = f"""Dear User,

🚨 Security Action Notification

Following the detection of suspicious network activity, our system has identified behavior consistent with a potential DDoS attack.

🔍 Incident Summary:

Event Type: Anomalous Traffic / Potential DDoS
Detection Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Source IP: {ip}

🚫 Automatic Defensive Action:
To protect your system, the identified source IP address has been automatically blocked by the Cyber Defensive Engine.

This action was taken to:

Prevent further malicious traffic
Maintain system stability
Reduce potential service disruption

🛡️ Current Status:

Threat contained ✔️
System operating normally ✔️
Continuous monitoring active ✔️

⚠️ Recommended Actions:

Review recent logs for additional suspicious activity
Verify no unauthorized access attempts were successful
Keep your system and security configurations up to date

🔐 Our system will continue monitoring for any further threats and take immediate action if required.

Stay secure,
Cyber Defensive Engine
Automated Security Monitoring System
"""

                    message = EmailMessage()
                    message['Subject'] = subject
                    message['From'] = sender_email
                    message['To'] = receiver_email
                    message.set_content(body)

                    alert(message)

                    os.system(
                        f"sudo iptables -C INPUT -s {ip} -j DROP || "
                        f"sudo iptables -A INPUT -s {ip} -j DROP"
                    )

            except Exception as e   :
                log.error(e)

def monitor_file(file) :
    while True  :
        if not os.path.exists(file) :
            print (f"{file} not found!")
            time.sleep(5)
            continue
        
        count = 0

        with open(file, 'r') as f:
            f.seek(0, os.SEEK_END)

            while True  :
                line = f.readline()

                if not line :
                    time.sleep(1)
                    continue

                
                line = line.lower()

                for p in SUSPICIOUS_PATTERNS :
                    if p in line    :
                        count += 1
                        break

                    if "accepted" in line   :
                        count = 0

                    if count >= THRESHOLD   :
                        count = 0

                        subject = "⚠️ Security Alert: Suspicious Login Activity Detected"

                        body = f"""🚨 Security Alert: Suspicious Activity Detected

Dear User,

This is an automated alert from your Security Monitoring System.

We have detected multiple suspicious login attempts that may indicate potential unauthorized access to your system.

--------------------------------------------------
🔍 Incident Details:
• File Monitored : {file}
• Timestamp      : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
--------------------------------------------------

⚠️ Recommended Actions:
• Review recent login activity immediately
• Verify all authorized users
• Change your passwords if necessary
• Enable additional security measures

If this activity was not initiated by you, please take immediate action.

🔐 Your security is our priority.

Stay safe,  
Security Monitoring System
"""

                        message = EmailMessage()
                        message['Subject'] = subject
                        message['From'] = sender_email
                        message['To'] = receiver_email
                        message.set_content(body)

                        if file == "/var/log/auth.log"  :
                            log.warning(f"Brute-force attack detected in (file)")
                        alert(message)

#---------Main------------------------
threads = []

unsupervised_learning()

t = threading.Thread(target = detection)
t.daemon = True
t.start()
threads.append(t)

for file in LOG_FILES    :
    t = threading.Thread(target = monitor_file, args = (file,))
    t.daemon = True
    t.start()
    threads.append(t)
    log.info(f"{file} monitoring started...")
    
    try :
        while True:
            time.sleep(1)
    except Exception as e   :
        log.error(e)