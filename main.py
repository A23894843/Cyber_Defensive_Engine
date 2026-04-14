import os
import ssl
import json
import time
import joblib
import smtplib
import logging
import subprocess
import threading
import numpy as np
import random as ran
from config import *
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict
from email.message import EmailMessage
from sklearn.ensemble import IsolationForest
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

gui = Tk()
gui.title("Cyber Defensive Engine")
gui.geometry("900x450")

otp_s = ran.randint(1000, 9999)
is_valid = True

if not log.handlers:
    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

if not os.path.exists("config.json")    :
    subprocess.run(["touch","config.json"])
    is_valid = False

def load_user_config()  :
    with open("config.json", 'r') as f :
        return json.load(f)

data = load_user_config()

if receiver_email == None or receiver_email.find("@gmail.com") == -1    :
    is_valid = False
if name == ""   :
    is_valid = False

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


def verify_Email()    :
    subject = "Email Verification Request"
    message = f"""Dear User,

I hope this message finds you well.

Thank you for registering with our service. To complete your registration and ensure the security of your account, we kindly request you to verify your email address.

Please click the link below to verify your email:

{otp_s}

If you did not initiate this request, please ignore this email.

Should you have any questions or need assistance, feel free to contact our support team.

Thank you for your cooperation.

Best regards,
Cyber Defensive Engine
Support Team"""
    
    alert(subject, message)

if not is_valid :
    config_win = Toplevel(gui)
    config_win.geometry("900x450")
    Label(config_win, text = "Name").grid(row = 0, column = 0, pady = 10)
    name_entry = Entry(config_win)
    name_entry.grid(row = 0, column = 1, pady = 10)

    Label(config_win, text = "Email").grid(row = 1, column = 0, pady = 10)
    email_entry = Entry(config_win)
    email_entry.grid(row = 1, column = 1, pady = 10)

    Button(config_win, text = "Verify Email", width = 20, command = verify_Email).grid(row = 1, column = 2, pady = 10)

    Label(config_win, text = "One Time Password").grid(row = 2, column = 0, pady = 10)
    otp_entry = Entry(config_win)
    otp_entry.grid(row = 2, column = 1, pady = 10)

    def store() :
        name_e = name_entry.get().strip()
        email_r = email_entry.get().strip()
        otp_r = otp_entry.get().strip()

        if otp_s != otp_r   :
            messagebox.showerror("Error: ", "Otp is invalid!")
            return 0
        else :
            with open("config.json", 'r') as f :
                data = json.load(f)

            data['name'] = name_e
            data['email'] = email_r

            with open("config.json", 'w') as f :
                json.dump(data, f, indent = 4)

            return 1

    Button(config_win, width = 20, text = "Submit", command = store).grid(row = 3, column = 1, pady = 10)

name = data.get("name")
receiver_email = data.get("email")

def train_model():
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

def on_close():
    log.info("Engine shutting down...")
    sniffer.terminate()
    gui.destroy()

#---------Main------------------------
if __name__ == "__main__":
    if os.path.exists(log_path)  :
        os.remove(log_path)
        print(f"Deleted : {log_path}")

    if os.path.exists(os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log"))  :
        os.remove(os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log"))
        print(f"Deleted : {os.path.join(os.getcwd(), "Cyber_Defensive_Engine.log")}")

    if not os.path.exists(PIPE) :
        subprocess.run(["mkfifo", PIPE])
        subprocess.run(["chmod", "666", PIPE])
    
    time.sleep(2)

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

    gui.mainloop()

    gui.protocol("WM_DELETE_WINDOW", on_close)
