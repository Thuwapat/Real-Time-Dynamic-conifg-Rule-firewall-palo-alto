import requests
import time
from session_funct import *
from rules_config_funct import *

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.15.5" 
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="  

POLL_INTERVAL = 1  # Secound
SESSION_THRESHOLD = 20  # Act session-per-IP
UNIQUE_IP_THRESHOLD = 1000  # Unique soucre IP

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global set to track already reported rules
existing_rules = set() 

print("-------- Start Real time DoS protection -----------")
while True:
    session_data = fetch_active_sessions(firewall_ip, api_key)
    if session_data is not None:
        session_count, unique_ip_count, zone_mapping = parse_sessions(session_data)

        # Check each Source IP for session threshold
        for src_ip, count in session_count.items():
            if count >= SESSION_THRESHOLD:
                print(">>>>>>>> DoS Detected !!!!! <<<<<<<<")
                src_zone, dst_zone = zone_mapping[src_ip]
                rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                create_dos_profile(firewall_ip, api_key, existing_rules)
                create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)

        # Check if unique IP count exceeds threshold
        if unique_ip_count >= UNIQUE_IP_THRESHOLD:
            for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                print(">>>>>>>>> DDoS Detected !!!!!! <<<<<<<<")
                rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                create_dos_profile(api_key)
                create_ddos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                break # for stop dulicate Zone rules

    else:
        print("No session data found.")

    time.sleep(POLL_INTERVAL)