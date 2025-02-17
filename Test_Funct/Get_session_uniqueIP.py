import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def fetch_all_active_sessions():
    """
    Fetch all active sessions from the Palo Alto firewall using pagination.
    """
    sessions = []
    start_point = 0  # Start from the first session
    batch_size = 1024  # Palo Alto's default API limit

    while True:
        url = f"https://{firewall_ip}/api/"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        payload = {
            'type': 'op',
            'cmd': f"<show><session><all></all><start-point>{start_point}</start-point></session></show>",
            'key': api_key
        }

        try:
            response = requests.post(url, headers=headers, data=payload, verify=False)
            if response.status_code == 200:
                response_xml = ET.fromstring(response.text)
                batch_sessions = response_xml.findall(".//entry")
                
                # Add batch to the total list of sessions
                sessions.extend(batch_sessions)
                
                # Break if less than batch_size fetched (no more sessions)
                if len(batch_sessions) < batch_size:
                    break
                else:
                    # Increment start_point for the next batch
                    start_point += batch_size
            else:
                print(f"Error fetching active sessions: HTTP {response.status_code} - {response.text}")
                break
        except Exception as e:
            print(f"Error fetching sessions: {e}")
            break

    return sessions


def parse_sessions(session_data):
    """
    Parse the active session data and calculate session counts for each source IP.
    Also track unique source IPs.
    """
    session_count = defaultdict(int)
    unique_ips = set()  # Use a set to track unique Source IPs

    # Find all session entries
    sessions = session_data.findall(".//entry")

    for session in sessions:
        source_ip = session.find('source').text  # Extract source IP
        if source_ip:
            session_count[source_ip] += 1
            unique_ips.add(source_ip)  # Add to the set of unique Source IPs

    return session_count, len(unique_ips)  # Return session count and unique IP count


def display_session_statistics(session_count, unique_ip_count):
    """
    Display session counts for each source IP and total number of unique Source IPs.
    """
    print("\n--- Active Session Counts by Source IP ---")
    for ip, count in session_count.items():
        print(f"Source IP: {ip}, Active Sessions: {count}")
    
    print("\n--- Total Unique Source IPs ---")
    print(f"Unique Source IPs: {unique_ip_count}")

    
if __name__ == "__main__":
    # Main loop to fetch and display session statistics periodically
    POLL_INTERVAL = 1  # Sec

    while True:
        session_data = fetch_all_active_sessions()
        if session_data is not None:
            session_count, unique_ip_count = parse_sessions(session_data)
            display_session_statistics(session_count, unique_ip_count)
        else:
            print("No session data found.")

        time.sleep(POLL_INTERVAL)
