import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
import time

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.15.5"  # Replace with your firewall IP
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="  # Replace with your API key

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def fetch_active_sessions():
    """
    Fetch the active sessions from the Palo Alto firewall.
    """
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Use the 'type=session' API call to get active sessions
    payload = {
        'type': 'op',
        'cmd': '<show><session><all></all></session></show>',
        'key': api_key
    }

    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            response_xml = ET.fromstring(response.text)
            return response_xml
        else:
            print(f"Error fetching active sessions: HTTP {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching sessions: {e}")
        return None


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
    POLL_INTERVAL = 1  # Time interval in seconds to fetch sessions and update statistics

    while True:
        session_data = fetch_active_sessions()
        if session_data is not None:
            session_count, unique_ip_count = parse_sessions(session_data)
            display_session_statistics(session_count, unique_ip_count)
        else:
            print("No session data found.")

        time.sleep(POLL_INTERVAL)
