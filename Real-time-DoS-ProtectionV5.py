import os
import time
import pickle
import threading
import pandas as pd
import requests
import sys
from session_funct import *
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
last_zone_rule_time = {}  
SLOWLORIS_ZONE_THRESHOLD = 2
ZONE_RULE_COOLDOWN = 60  

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

            rules_to_create = []  # Store Rules that have to create
            ips_to_clear = set()  # Store IP to be cleared
            is_high_unique_ip_ddos = False  
            
            # Check DoS and Store DoS IP
            dos_ips = set()
            if predicted_attack == 1 or predicted_attack == 2:
                print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
                for src_ip, count in session_count.items():
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                    if rule_name not in existing_rules and count >= ACTIVESESSION_THRESHOLD:
                        print(f"Preparing rule to block DoS from {src_ip} with {count} sessions")
                        rules_to_create.append((src_ip, src_zone, dst_zone, rule_name))
                    ips_to_clear.add(src_ip)
                    dos_ips.add(src_ip)
            
            # Check DDoS 
            current_time = time.time()
            if len(dos_ips) >= DDOS_IP_THRESHOLD:
                print(">>>>>>>>> DDoS Detected: Multiple DoS IPs !!!!!! <<<<<<<<")
                for src_ip in dos_ips: 
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    zone_key = f"{src_zone}_to_{dst_zone}"
                    last_time = last_zone_rule_time.get(zone_key, 0)
                    if rule_name not in existing_rules and (current_time - last_time >= ZONE_RULE_COOLDOWN):
                        print(f"Preparing rule to block zone {src_zone} to {dst_zone} due to DDoS (Multiple DoS IPs)")
                        rules_to_create.append(("any", src_zone, dst_zone, rule_name))
                        last_zone_rule_time[zone_key] = current_time
            
            # Check Unique IP 
            elif unique_ip_count >= DDOS_UNIQUE_IP_THRESHOLD:
                print(">>>>>>>>> DDoS Detected: High Unique IP Count !!!!!! <<<<<<<<")
                is_high_unique_ip_ddos = True # DDoS => IF have many Unique IP 
                for src_ip, (src_zone, dst_zone) in list(zone_mapping.items())[:1]: 
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    zone_key = f"{src_zone}_to_{dst_zone}"
                    last_time = last_zone_rule_time.get(zone_key, 0)
                    if rule_name not in existing_rules and (current_time - last_time >= ZONE_RULE_COOLDOWN):
                        print(f"Preparing rule to block zone {src_zone} to {dst_zone} due to high unique IP count ({unique_ip_count})")
                        rules_to_create.append(("any", src_zone, dst_zone, rule_name))
                        last_zone_rule_time[zone_key] = current_time
            
            # Detect Slowloris
            if traffic_logs:
                slowloris_candidates = detect_slowloris_from_logs(traffic_logs, threshold_matches=5)
                if slowloris_candidates:
                    print(">>>>>>>> Slowloris Attack Detected from Traffic Logs !!!!!! <<<<<<<<")
                    current_time = time.time()
                    
                    # Count Source IP Slowloris Detected
                    slowloris_ip_count = len(slowloris_candidates)
                    
                    if slowloris_ip_count >= SLOWLORIS_ZONE_THRESHOLD:
                        #  2 IP Create Zone-based Rule
                        print(f">>>>>>> Multiple Slowloris Sources Detected ({slowloris_ip_count} IPs) - Switching to Zone-based Blocking <<<<<<<<")
                        zones_to_block = set() 
                        for src_ip, candidate_info in slowloris_candidates.items():
                            src_zone = candidate_info['src_zone']
                            dst_zone = candidate_info['dst_zone']
                            zones_to_block.add((src_zone, dst_zone))
                            ips_to_clear.add(src_ip)  
                        
                        for src_zone, dst_zone in zones_to_block:
                            rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                            zone_key = f"{src_zone}_to_{dst_zone}"
                            last_time = last_zone_rule_time.get(zone_key, 0)
                            if rule_name not in existing_rules and (current_time - last_time >= ZONE_RULE_COOLDOWN):
                                print(f"Preparing rule to block zone {src_zone} to {dst_zone} due to multiple Slowloris sources ({slowloris_ip_count} IPs)")
                                rules_to_create.append(("any", src_zone, dst_zone, rule_name))
                                last_zone_rule_time[zone_key] = current_time
                    else:
                        # 1 IP Create IP Base
                        for src_ip, candidate_info in slowloris_candidates.items():
                            match_count = candidate_info['match_count']
                            src_zone = candidate_info['src_zone']
                            dst_zone = candidate_info['dst_zone']
                            rule_name = f"Block_Slowloris_{src_ip.replace('.', '_')}"
                            if rule_name not in existing_rules and src_zone and dst_zone:
                                print(f"Preparing rule to block Slowloris from {src_ip} ({match_count} matching logs)")
                                rules_to_create.append((src_ip, src_zone, dst_zone, rule_name))
                            ips_to_clear.add(src_ip)

            if int(time.time()) % 10 == 0:
                existing_rules.update(sync_existing_rules())
            # Create new Rules
            for src_ip, src_zone, dst_zone, rule_name in rules_to_create:
                create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules, commit=False)

            # Commit and Clear Session if have new rules or SUS IP 
            if rules_to_create or (ips_to_clear and not is_high_unique_ip_ddos):
                if rules_to_create:
                    commit_changes(firewall_ip, api_key)  
                    all_rules_ready = True
                    for src_ip, src_zone, dst_zone, rule_name in rules_to_create:
                        result = get_rule_last_hit_payload(rule_name)
                        if not isinstance(result, ET.Element):
                            print(f"Error: get_rule_last_hit_payload returned invalid result for {rule_name}: {result}")
                            all_rules_ready = False
                            continue
                        
                        creation_elem = result.find(".//rules/entry/rule-creation-timestamp")
                        if creation_elem is not None and hasattr(creation_elem, 'text') and creation_elem.text is not None:
                            try:
                                creation_time = int(creation_elem.text.strip())
                                print(f"Rule {rule_name} created with creation time {creation_time}")
                                existing_rules.add(rule_name)
                            except ValueError:
                                print(f"Error: Invalid creation time format for {rule_name}: {creation_elem.text}")
                                all_rules_ready = False
                        else:
                            print(f"Rule {rule_name} created but no valid creation time found. creation_elem: {creation_elem}")
                            all_rules_ready = False
                
                # Clear Session in ips_to_clear 
                if ips_to_clear and not is_high_unique_ip_ddos:
                    if (rules_to_create and all_rules_ready) or not rules_to_create:
                        for src_ip in ips_to_clear:
                            clear_sessions(firewall_ip, api_key, src_ip)
                        print("Sessions cleared for detected IPs.")
                    else:
                        print("Some new rules are not ready, skipping session clear.")
            
            if dos_ips and len(dos_ips) < DDOS_IP_THRESHOLD:
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