import requests
import time
import numpy as np
from stable_baselines3 import DQN
from session_funct import *
from rules_config_funct import *


firewall_ip = "192.168.15.5"
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="

POLL_INTERVAL = 1  # Seconds

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global set to track already reported rules
existing_rules = set()

# Load the trained model
rl_model = DQN.load("dos_rl_agent")

print("-------- Start Real-Time DoS/DDoS Protection with RL --------")

while True:
    # Fetch session statistics
    session_data = fetch_info_sessions(firewall_ip, api_key)
    actsession_data = fetch_active_sessions(firewall_ip, api_key)

    if session_data is not None:
        # Extract session statistics
        cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps = parse_info_sessions(session_data)
        session_count, unique_ip_count, zone_mapping = parse_act_sessions(actsession_data)

        features = np.array([[float(cps), float(kbps), float(num_active), float(num_icmp), float(num_tcp), float(num_udp), float(pps)]], dtype=np.float32)
        print(features)
        
        action, _ = rl_model.predict(features)
        
        if action == 0:
            print(" No Action Taken (RL Decision)")
        elif action == 1:
            print(" RL Decision: DoS Detected")
            for src_ip, count in session_count.items():
                src_zone, dst_zone = zone_mapping[src_ip]
                rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                #create_dos_profile(firewall_ip, api_key, existing_rules)
                #create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)

        elif action == 2:
            print(" RL Decision: DDoS Detected")
            for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                #create_dos_profile(firewall_ip, api_key, existing_rules)
                #create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)
                break  # Prevent duplicate zone rules

    else:
        print(" No session data found.")

    time.sleep(POLL_INTERVAL)
