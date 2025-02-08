import pandas as pd
import time
from session_funct import fetch_info_sessions, fetch_active_sessions, parse_act_sessions  # Import functions from session_funct

# Palo Alto Firewall Configuration
firewall_ip = "192.168.15.5"
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="

# Function to save session data to CSV
def save_to_csv(data, filename="session_infoNormal.csv"):
    df = pd.DataFrame([data])
    try:
        with open(filename, "r", encoding="utf-8") as file:
            df.to_csv(filename, mode="a", index=False, header=False, encoding="utf-8")
    except FileNotFoundError:
        df.to_csv(filename, mode="w", index=False, header=True, encoding="utf-8")

# Main function to collect session data
def main():
    duration = 15 * 60  # Run for 15 minutes
    start_time = time.time()
    print("Starting data collection for 15 minutes...")
    
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > duration:
            print("Completed 15 minutes of data collection. Stopping now.")
            break
        
        # Fetch session data using function from session_funct.py
        session_data = fetch_info_sessions(firewall_ip, api_key)
        actsession_data = fetch_active_sessions(firewall_ip, api_key)
        
        if session_data and actsession_data:
            # Parse the session data
            parsed_data = {
                "cps": session_data.find('cps').text if session_data.find('cps') else '0',
                "kbps": session_data.find('kbps').text if session_data.find('kbps') else '0',
                "num-active": session_data.find('num-active').text if session_data.find('num-active') else '0',
                "num-icmp": session_data.find('num-icmp').text if session_data.find('num-icmp') else '0',
                "num-tcp": session_data.find('num-tcp').text if session_data.find('num-tcp') else '0',
                "num-udp": session_data.find('num-udp').text if session_data.find('num-udp') else '0',
                "pps": session_data.find('pps').text if session_data.find('pps') else '0'
            }
            
            # Parse active session data to get unique IPs
            actsession_count, unique_src_count, unique_dst_count, zone_mapping = parse_act_sessions(actsession_data)
            parsed_data["unique_source_ips"] = unique_src_count
            parsed_data["unique_destination_ips"] = unique_dst_count
            
            # Save parsed data to CSV
            save_to_csv(parsed_data)
            print("Saved data:", parsed_data)
        
        time.sleep(0.25)  # Collect data every 0.25 seconds

if __name__ == "__main__":
    main()
