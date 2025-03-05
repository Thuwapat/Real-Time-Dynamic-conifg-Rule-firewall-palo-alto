# main.py
import os
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
POLL_INTERVAL = 1  # Seconds
UNIQUE_IP_THRESHOLD = 1024
ACTIVESESSION_THRESHOLD = 1024
LOG_SAMPLING_SIZE = 100

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

existing_rules = set()

with open('dos_detection_modelV3.pkl', 'rb') as model_file:
    ml_model = pickle.load(model_file)

print("-------- Start Real-Time DoS/DDoS Protection with ML --------")

def detection_loop():
    while True:
        session_data = fetch_info_sessions(firewall_ip, api_key)
        actsession_data = fetch_active_sessions(firewall_ip, api_key)
        print(f"Fetching {LOG_SAMPLING_SIZE} new traffic logs...")
        traffic_logs = get_new_traffic_logs(api_key, max_logs=LOG_SAMPLING_SIZE)
        
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
            
            if traffic_logs and len(traffic_logs) == LOG_SAMPLING_SIZE:  # Ensure we got 100 logs
                slowloris_candidates = detect_slowloris_from_logs(traffic_logs, threshold_matches=5)
                if slowloris_candidates:
                    print(">>>>>>>> Slowloris Attack Detected from Traffic Logs !!!!!! <<<<<<<<")
                    for src_ip, match_count in slowloris_candidates.items():
                        src_zone = zone_mapping.get(src_ip, ("unknown", "unknown"))[0]
                        dst_zone = zone_mapping.get(src_ip, ("unknown", "unknown"))[1]
                        rule_name = f"Block_Slowloris_{src_ip.replace('.', '_')}"
                        if rule_name not in existing_rules:
                            print(f"Creating rule to block Slowloris from {src_ip} ({match_count} matching logs)")
                            existing_rules.add(rule_name)
                else:
                    print("No Slowloris candidates detected in this batch.")
            else:
                print(f"Failed to retrieve 100 new logs. Got {len(traffic_logs) if traffic_logs else 0} logs instead.")
            
            if predicted_attack == 1:
                print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
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
        for rule in list(existing_rules):
            check_and_remove_rule(rule, existing_rules)
        time.sleep(5)

detection_thread = threading.Thread(target=detection_loop, name="DetectionThread", daemon=True)
rule_check_thread = threading.Thread(target=rule_check_loop, name="RuleCheckThread", daemon=True)

detection_thread.start()
rule_check_thread.start()

detection_thread.join()
rule_check_thread.join()