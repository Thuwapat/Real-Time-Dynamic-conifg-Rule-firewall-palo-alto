import pandas as pd
import os
import requests
import time
from session_funct import fetch_info_sessions, fetch_active_sessions, parse_act_sessions, parse_info_sessions  # Import functions from session_funct

# Palo Alto Firewall Configuration
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to save session data to CSV
def save_to_csv(data, folder = "dataset", filename="session_info_Dos_TCP.csv"):
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_path = os.path.join(folder, filename)

    df = pd.DataFrame([data])
    
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            df.to_csv(file_path, mode="a", index=False, header=False, encoding="utf-8")
    except FileNotFoundError:
        df.to_csv(file_path, mode="w", index=False, header=True, encoding="utf-8")

# Main function to collect session data
def main():
    duration = 20*60
    start_time = time.time()
    print("Starting data collection for 15 minutes...")
    
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > duration:
            print("Completed 15 minutes of data collection. Stopping now.")
            break
        
        # Fetch session data using function from session_funct.py
        session_data = fetch_info_sessions(firewall_ip, api_key)
        #actsession_data = fetch_active_sessions(firewall_ip, api_key)
        
        if session_data is not None:
        # Extract session statistics
            cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps = parse_info_sessions(session_data)
            parsed_data = {
                "cps": cps,
                "kbps": kbps,
                "num_active": num_active,
                "num_icmp": num_icmp,
                "num_tcp": num_tcp,
                "num_udp": num_udp,
                "pps": pps
            }
            
            # Parse active session data to get unique IPs
            #actsession_count, unique_src_count, unique_dst_count, zone_mapping = parse_act_sessions(actsession_data)
            #parsed_data["unique_source_ips"] = unique_src_count
            #parsed_data["unique_destination_ips"] = unique_dst_count
            
            # Save parsed data to CSV
            save_to_csv(parsed_data)
            print("Saved data:", parsed_data)
        
        time.sleep(0.10)

if __name__ == "__main__":
    main()
