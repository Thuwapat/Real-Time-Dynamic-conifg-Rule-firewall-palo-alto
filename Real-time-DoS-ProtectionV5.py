import os
import time
import pickle
import threading
import pandas as pd
import requests
import sys
from session_funct import *
from rules_config_funct import *
from rules_manager import *
from Slowloris_Detection import detect_slowloris_from_logs
from Get_traffic_logs import get_new_traffic_logs

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

POLL_INTERVAL = 1 
UNIQUE_IP_THRESHOLD = 1024  
ACTIVESESSION_THRESHOLD = 1024
LOG_SAMPLING_SIZE = 100
DDOS_IP_THRESHOLD = 2 
DDOS_UNIQUE_IP_THRESHOLD = 1024

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
stop_event = threading.Event()
existing_rules = set()

with open('dos_detection_model.pkl', 'rb') as model_file:
    ml_model = pickle.load(model_file)

print("-------- Start Real-Time DoS/DDoS Protection with ML --------")

def detection_loop():
    create_dos_profile(firewall_ip, api_key)
    while not stop_event.is_set():
        session_data = fetch_info_sessions(firewall_ip, api_key)
        actsession_data = fetch_active_sessions(firewall_ip, api_key)
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
            predicted_attack = ml_model.predict(feature_vector)[0]
            
            # ตรวจจับ Slowloris
            if traffic_logs:
                slowloris_candidates = detect_slowloris_from_logs(traffic_logs, threshold_matches=5)
                if slowloris_candidates:
                    print(">>>>>>>> Slowloris Attack Detected from Traffic Logs !!!!!! <<<<<<<<")
                    for src_ip, candidate_info in slowloris_candidates.items():
                        match_count = candidate_info['match_count']
                        src_zone = candidate_info['src_zone']
                        dst_zone = candidate_info['dst_zone']
                        rule_name = f"Block_Slowloris_{src_ip.replace('.', '_')}"
                        if rule_name not in existing_rules:
                            if src_zone and dst_zone: 
                                print(f"Creating rule to block Slowloris from {src_ip} ({match_count} matching logs)")
                                create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                                # ตรวจสอบ creation time และล้าง session
                                result = get_rule_last_hit_payload(rule_name)
                                creation_elem = result.find(".//rules/entry/rule-creation-timestamp")
                                if creation_elem is not None and creation_elem.text is not None:
                                    print(f"Rule {rule_name} created with creation time {creation_elem.text}")
                                    clear_sessions(firewall_ip, api_key, src_ip)  # ล้าง session เดิม
                                    existing_rules.add(rule_name)
                                else:
                                    print(f"Rule {rule_name} created but no creation time yet, skipping session clear.")
            
            # Check DoS and Store DoS IP IF >= 2 this is DDoS
            dos_ips = set()  
            if predicted_attack == 1 or predicted_attack == 2:
                print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
                for src_ip, count in session_count.items():
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                    if rule_name not in existing_rules:
                        if count >= ACTIVESESSION_THRESHOLD:
                            print(f"DoS detected from {src_ip} with {count} sessions")
                            create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                            # ตรวจสอบ creation time และล้าง session
                            result = get_rule_last_hit_payload(rule_name)
                            creation_elem = result.find(".//rules/entry/rule-creation-timestamp")
                            if creation_elem is not None and creation_elem.text is not None:
                                print(f"Rule {rule_name} created with creation time {creation_elem.text}")
                                clear_sessions(firewall_ip, api_key, src_ip)  # ล้าง session เดิม
                                existing_rules.add(rule_name)
                            else:
                                print(f"Rule {rule_name} created but no creation time yet, skipping session clear.")
                            dos_ips.add(src_ip)
            
            # Check DDoS 
            if len(dos_ips) >= DDOS_IP_THRESHOLD:
                print(">>>>>>>>> DDoS Detected: Multiple DoS IPs !!!!!! <<<<<<<<")
                for src_ip in dos_ips: 
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    if rule_name not in existing_rules:
                        print(f"Creating rule to block zone {src_zone} to {dst_zone} due to DDoS (Multiple DoS IPs)")
                        create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)
            
            # Check Unique IP 
            elif unique_ip_count >= DDOS_UNIQUE_IP_THRESHOLD:
                print(">>>>>>>>> DDoS Detected: High Unique IP Count !!!!!! <<<<<<<<")
                for src_ip, (src_zone, dst_zone) in list(zone_mapping.items())[:1]: 
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    if rule_name not in existing_rules:
                        print(f"Creating rule to block zone {src_zone} to {dst_zone} due to high unique IP count ({unique_ip_count})")
                        create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)
                        existing_rules.add(rule_name)
            
            elif dos_ips:
                print(f"DoS detected from {len(dos_ips)} IP(s), not enough for DDoS (threshold: {DDOS_IP_THRESHOLD})")
            else:
                print(f"..................................")
        
        else:
            print("No session data found.")
        
        time.sleep(POLL_INTERVAL)

def rule_check_loop():
    while not stop_event.is_set():
        print("..............Checking rules..............")
        for rule in list(existing_rules):
            check_and_remove_rule(rule, existing_rules)
        time.sleep(60)

def input_loop():
    while not stop_event.is_set():
        user_input = input().strip().lower()
        if user_input == 'q':
            print("Received 'q'. Shutting down...")
            stop_event.set()  
            break

detection_thread = threading.Thread(target=detection_loop, name="DetectionThread", daemon=True)
rule_check_thread = threading.Thread(target=rule_check_loop, name="RuleCheckThread", daemon=True)
input_thread = threading.Thread(target=input_loop, name="InputThread", daemon=True)

detection_thread.start()
rule_check_thread.start()
input_thread.start()

detection_thread.join()
rule_check_thread.join()
input_thread.join()

print("Program has stopped.")
sys.exit(0)