# main.py
import os
import time
import pickle
import threading
import pandas as pd
import requests
from session_funct import *
from rules_config_funct import *
# Import ฟังก์ชันจาก rules_manager.py
from rules_manager import *

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
POLL_INTERVAL = 1  # Seconds
UNIQUE_IP_THRESHOLD = 1020

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global set to track already reported rules
existing_rules = set()

# Load the ML model
with open('dos_detection_model.pkl', 'rb') as model_file:
    ml_model = pickle.load(model_file)

print("-------- Start Real-Time DoS/DDoS Protection with ML --------")

def detection_loop():
    while True:
        # Fetch session statistics
        session_data = fetch_info_sessions(firewall_ip, api_key)
        actsession_data = fetch_active_sessions(firewall_ip, api_key)
        
        if session_data is not None:
            cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps = parse_info_sessions(session_data)
            session_count, unique_ip_count, zone_mapping = parse_act_sessions(actsession_data)
            
            features = {
                'cps': cps,
                'kbps': kbps,
                'num_active': num_active,
                'num_icmp': num_icmp,
                'num_tcp': num_tcp,
                'num_udp': num_udp,
                'pps': pps
            }
            
            with open('scaler.pkl', 'rb') as scaler_file:
                scaler = pickle.load(scaler_file)
            
            feature_vector = pd.DataFrame([features])
            predicted_attack = ml_model.predict(feature_vector)[0]
            print(f"Predicted Attack Type: {predicted_attack}")
            
            if predicted_attack == 1:  # DoS attack
                print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
                for src_ip, count in session_count.items():
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                    if rule_name not in existing_rules:
                        create_dos_profile(firewall_ip, api_key, existing_rules)
                        create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)
            elif predicted_attack == 2 and unique_ip_count >= UNIQUE_IP_THRESHOLD:  # DDoS attack
                print(">>>>>>>>> DDoS Detected by ML !!!!!! <<<<<<<<")
                for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    if rule_name not in existing_rules:
                        create_dos_profile(firewall_ip, api_key, existing_rules)
                        create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)
                    break  # หยุดสร้าง rule ซ้ำสำหรับ zone เดียวกัน
        else:
            print("No session data found.")
        
        time.sleep(POLL_INTERVAL)

def rule_check_loop():
    while True:
        print("------ Checking rules ------")
        for rule in list(existing_rules):
            check_and_remove_rule(rule, existing_rules)
        time.sleep(5)

# ใช้ threading เพื่อรัน detection_loop และ rule_check_loop พร้อมกัน
detection_thread = threading.Thread(target=detection_loop, name="DetectionThread")
rule_check_thread = threading.Thread(target=rule_check_loop, name="RuleCheckThread")

detection_thread.start()
rule_check_thread.start()

detection_thread.join()
rule_check_thread.join()
