# main.py
import os
import datetime 
import time
import pickle
import threading
import pandas as pd
import requests
from session_funct import *
from rules_config_funct import *
from rules_manager import *
from Slowloris_Detection import detect_slowloris_from_logs
from Get_traffic_logs import get_new_traffic_logs

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
POLL_INTERVAL = 1  # Seconds for main detection loop
SLOWLORIS_POLL_INTERVAL = 0.5  # Faster polling for Slowloris
UNIQUE_IP_THRESHOLD = 1024
ACTIVESESSION_THRESHOLD = 1024
LOG_SAMPLING_SIZE = 100

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Use a Lock to safely manage existing_rules across threads
rules_lock = threading.Lock()
existing_rules = set()

with open('dos_detection_modelV3.pkl', 'rb') as model_file:
    ml_model = pickle.load(model_file)

print("-------- Start Real-Time DoS/DDoS Protection with ML --------")

def slowloris_detection_loop():
    """Dedicated thread for Slowloris detection."""
    while True:
        fetch_time = datetime.now()
        print(f"[Slowloris Thread] Starting log fetch at {fetch_time}")
        traffic_logs = get_new_traffic_logs(api_key, max_logs=LOG_SAMPLING_SIZE)
        
        if traffic_logs:
            slowloris_candidates = detect_slowloris_from_logs(traffic_logs, fetch_time, threshold_connections=5, time_window=2)
            if slowloris_candidates:
                print("[Slowloris Thread] >>>>>>>> Slowloris Attack Detected from Traffic Logs !!!!!! <<<<<<<<")
                with rules_lock:  # Safely update rules
                    for src_ip, session_count in slowloris_candidates.items():
                        # Fetch zone_mapping in this thread if needed, or pass it from main thread
                        # For simplicity, we'll assume zones are "unknown" here; adjust as needed
                        src_zone = "unknown"
                        dst_zone = "unknown"
                        rule_name = f"Block_Slowloris_{src_ip.replace('.', '_')}"
                        if rule_name not in existing_rules:
                            print(f"[Slowloris Thread] Creating rule to block Slowloris from {src_ip} ({session_count} concurrent sessions)")
                            existing_rules.add(rule_name)
            else:
                print("[Slowloris Thread] No Slowloris candidates detected in this cycle.")
        else:
            print("[Slowloris Thread] No new traffic logs retrieved.")
        
        time.sleep(SLOWLORIS_POLL_INTERVAL)

def detection_loop():
    """Main thread for DoS/DDoS detection."""
    while True:
        session_data = fetch_info_sessions(firewall_ip, api_key)
        actsession_data = fetch_active_sessions(firewall_ip, api_key)
        
        if session_data is not None and actsession_data is not None:
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
            
            feature_vector = pd.DataFrame([features])
            print(feature_vector)
            predicted_attack = ml_model.predict(feature_vector)[0]
            print(f"Predicted Attack Type: {predicted_attack}")
            print(f"Existing rules: {existing_rules}")
            
            if predicted_attack == 1:
                print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
                with rules_lock:
                    for src_ip, count in session_count.items():
                        src_zone, dst_zone = zone_mapping[src_ip]
                        rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                        if rule_name in existing_rules:
                            print(f"Rule {rule_name} already exists..skipping creation")
                            continue
                        if count >= ACTIVESESSION_THRESHOLD:
                            existing_rules.add(rule_name)
            elif predicted_attack == 2 and unique_ip_count >= UNIQUE_IP_THRESHOLD:
                print(">>>>>>>>> DDoS Detected by ML !!!!!! <<<<<<<<")
                with rules_lock:
                    for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                        rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                        if rule_name not in existing_rules:
                            existing_rules.add(rule_name)
                        break  
        else:
            print("No session data found.")
        
        time.sleep(POLL_INTERVAL)

def rule_check_loop():
    while True:
        print("------ Checking rules ------")
        with rules_lock:
            for rule in list(existing_rules):
                check_and_remove_rule(rule, existing_rules)
        time.sleep(5)

# Start threads
detection_thread = threading.Thread(target=detection_loop, name="DetectionThread", daemon=True)
slowloris_thread = threading.Thread(target=slowloris_detection_loop, name="SlowlorisThread", daemon=True)
rule_check_thread = threading.Thread(target=rule_check_loop, name="RuleCheckThread", daemon=True)

detection_thread.start()
slowloris_thread.start()
rule_check_thread.start()

detection_thread.join()
slowloris_thread.join()
rule_check_thread.join()