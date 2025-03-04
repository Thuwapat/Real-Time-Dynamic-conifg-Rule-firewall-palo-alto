import requests
import time
import pickle
import pandas as pd
from session_funct import *
from rules_config_funct import *
from rules_manager import *
import os 

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
POLL_INTERVAL = 1  # Seconds

#SESSION_THRESHOLD = 20  # Active session-per-IP threshold
UNIQUE_IP_THRESHOLD = 1020 # Unique source IP threshold

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Initialize seen IPs storage
seen_ips = set() 

# Global set to track already reported rules
existing_rules = set() 

# Load the ML model
with open('dos_detection_model.pkl', 'rb') as model_file:
    ml_model = pickle.load(model_file)

print("-------- Start Real-Time DoS/DDoS Protection with ML --------")

while True:
    # Fetch session statistics
    session_data = fetch_info_sessions(firewall_ip, api_key)
    actsession_data = fetch_active_sessions(firewall_ip, api_key)
    
    if session_data is not None:
        # Extract session statistics
        cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps = parse_info_sessions(session_data)
        session_count, unique_ip_count, zone_mapping = parse_act_sessions(actsession_data, seen_ips)
        
        # Prepare feature vector for ML prediction
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
        #feature_vector_scaled = scaler.transform(feature_vector)
        #feature_vector_scaled_df = pd.DataFrame(feature_vector_scaled, columns=feature_vector.columns)

        #print(ml_model.feature_names_in_)
        
        print(feature_vector)
        #print(feature_vector_scaled)

        # Predict attack type
        predicted_attack = ml_model.predict(feature_vector)[0]
        print(f"Predicted Attack Type: {predicted_attack}")


        # Trigger protections based on predictions
        if predicted_attack == 1:  # DoS attack
            print(">>>>>>>> DoS Detected by ML !!!!! <<<<<<<<")
            print(existing_rules)
            for src_ip, count in session_count.items():
                src_zone, dst_zone = zone_mapping[src_ip]
                rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                create_dos_profile(firewall_ip, api_key, existing_rules)
                create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules)
                
        elif predicted_attack == 2 & unique_ip_count >= UNIQUE_IP_THRESHOLD:  # DDoS attack
            print(">>>>>>>>> DDoS Detected by ML !!!!!! <<<<<<<<")
            print(existing_rules)
            for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                create_dos_profile(firewall_ip, api_key, existing_rules)
                create_dos_protection_policy(firewall_ip, api_key, "any", src_zone, dst_zone, rule_name, existing_rules)   
                break # for stop dulicate Zone rules
        
    else:
        print("No session data found.")

    time.sleep(POLL_INTERVAL)
