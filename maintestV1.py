# main.py
import os
import time
import pickle
import threading
import numpy as np
import joblib
import pandas as pd
import requests
from Get_onlynew_traffic import get_new_traffic_logs # ดึงข้อมูลจาก Get_traffic.py
from rules_config_funct import *
from rules_manager import *
from sklearn.preprocessing import LabelEncoder
# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
POLL_INTERVAL = 1  # Seconds
UNIQUE_IP_THRESHOLD = 1020

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global set to track already reported rules
existing_rules = set()

# Load the updated ML model
with open('RandomForest_Traffic_Model.pkl', 'rb') as model_file:
    ml_model = joblib.load(model_file)

print(f"✅ Loaded Model: {type(ml_model)}")

try:
    with open("label_encoders.pkl", "rb") as le_file:
        label_encoders = joblib.load(le_file)
except FileNotFoundError:
    label_encoders = {}

print("-------- Start Real-Time DoS/DDoS Protection with ML (Updated) --------")

def preprocess_traffic_log(log):
    """ แปลงข้อมูล Traffic Log ให้เป็น Feature Vector ที่โมเดลต้องการ """

    # แปลงค่าโปรโตคอลจากชื่อ (string) เป็นตัวเลข
    protocol_mapping = {"tcp": 6, "udp": 17, "icmp": 1}
    ip_protocol = protocol_mapping.get(log.get("proto", "").lower(), 0)  # ค่า default เป็น 0 ถ้าไม่พบ

    return {
        "Application": log.get("app", "unknown"),  # ต้องแปลงเป็นตัวเลข
        "Repeat Count": int(log.get("repeatcnt", 1)),
        "IP Protocol": ip_protocol,
        "Bytes": int(log.get("bytes", 0)),
        "Bytes Sent": int(log.get("bytes_sent", 0)),
        "Bytes Received": int(log.get("bytes_received", 0)),
        "Packets": int(log.get("packets", 0)),
        "Elapsed Time (sec)": float(log.get("elapsed", 1.0)),
        "Packets Sent": int(log.get("pkts_sent", 0)),
        "Packets Received": int(log.get("pkts_received", 0)),
        "Session End Reason": log.get("session_end_reason", "unknown"),  # ต้องแปลงเป็นตัวเลข
        "Risk of app": int(log.get("risk_of_app", 1)),
        "Characteristic of app": log.get("characteristic_of_app", "unknown"),  # ต้องแปลงเป็นตัวเลข
        "Packets per second": int(log.get("packets", 0)) / (float(log.get("elapsed", 1.0)) + 1e-5),
        "Bytes per second": int(log.get("bytes", 0)) / (float(log.get("elapsed", 1.0)) + 1e-5),
        "Average packet size": int(log.get("bytes", 0)) / (int(log.get("packets", 1)) + 1e-5)
    }

def detection_loop():
    while True:
        logs = get_new_traffic_logs(api_key, log_type="traffic", max_logs=5)

        if logs:
            for log in logs:
                # แปลงข้อมูล Log เป็น Feature Vector
                features = preprocess_traffic_log(log)

                # แปลง String Features เป็นตัวเลขโดยใช้ Label Encoding ที่ถูกต้อง
                string_features = ["Application", "Session End Reason", "Characteristic of app"]
                for col in string_features:
                    if col not in label_encoders:
                        label_encoders[col] = LabelEncoder()
                        label_encoders[col].fit([features[col]])  # Fit เฉพาะค่าเดียวก่อน

                    # ✅ แก้ไขปัญหา "unseen label" โดยใช้ `classes_`
                    if features[col] not in label_encoders[col].classes_:
                        label_encoders[col].classes_ = np.append(label_encoders[col].classes_, features[col])

                    features[col] = label_encoders[col].transform([features[col]])[0]

                # แปลงเป็น DataFrame ก่อนให้โมเดลทำนาย
                feature_vector = pd.DataFrame([features])

                # ทำนายประเภทของการโจมตี
                predicted_attack = ml_model.predict(feature_vector)[0]
                print(f"Predicted Attack Type: {predicted_attack}")

                # ถ้าเป็น DoS หรือ DDoS ให้สร้าง Rule เพื่อ Block
                if predicted_attack == 1:  # DoS attack
                    print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
                    src_ip = log.get("src")
                    dst_ip = log.get("dst")
                    src_zone = log.get("from")
                    dst_zone = log.get("to")  # แก้ให้เหมาะกับ network ของคุณ
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"

                    if rule_name not in existing_rules:
                        #create_dos_profile(firewall_ip, api_key, existing_rules)
                        #create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)

                elif predicted_attack == 2:  # DDoS attack
                    print(">>>>>>>>> DDoS Detected by ML !!!!!! <<<<<<<<")
                    src_zone = log.get("from")
                    dst_ip = log.get("dst")
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"

                    if rule_name not in existing_rules:
                        #create_dos_profile(firewall_ip, api_key, existing_rules)
                        #create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)

        else:
            print("No traffic logs found.")

        time.sleep(POLL_INTERVAL)

def rule_check_loop():
    while True:
        print("------ Checking rules ------")
        for rule in list(existing_rules):
            check_and_remove_rule(rule, existing_rules)
        time.sleep(5)

# ใช้ threading เพื่อรัน detection_loop และ rule_check_loop พร้อมกัน
#detection_thread = threading.Thread(target=detection_loop, name="DetectionThread")
#rule_check_thread = threading.Thread(target=rule_check_loop, name="RuleCheckThread")

#detection_thread.start()
#rule_check_thread.start()
detection_loop()
#detection_thread.join()
#rule_check_thread.join()
