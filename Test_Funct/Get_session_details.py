import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings (optional but recommended for testing environments)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def fetch_active_sessions():
    """
    Fetch the active sessions from the Palo Alto firewall.
    Returns the session data in XML format or None in case of an error.
    """
    url = f"https://{firewall_ip}/api/"
    payload = {
        'type': 'op',
        'cmd': '<show><session><all></all></session></show>',
        'key': api_key
    }

    try:
        response = requests.post(url, data=payload, verify=False)
        response.raise_for_status()  # Raise an HTTPError for bad HTTP responses
        return ET.fromstring(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching active sessions: {e}")
        return None
    except ET.ParseError as e:
        print(f"Error parsing XML response: {e}")
        return None


def parse_sessions(session_data):
    """
    Parse the active session data and return:
    1. List of session details (dictionary for each session)
    2. Dictionary of session counts per source IP
    """
    session_details = []
    session_count = defaultdict(int)

    # Find all session entries
    sessions = session_data.findall(".//entry")
    for session in sessions:
        try:
            source_ip = session.findtext('source', default="N/A")
            session_count[source_ip] += 1  # Increment session count for source IP

            # Collect session details in a dictionary
            session_details.append({
                "Source IP": source_ip,
                "Destination IP": session.findtext('dst', default="N/A"),
                "Src Zone": session.findtext('from', default="N/A"),
                "Dst Zone": session.findtext('to', default="N/A"),
                "Source Port": session.findtext('sport', default="N/A"),
                "Destination Port": session.findtext('dport', default="N/A"),
                "Application": session.findtext('application', default="N/A"),
                "Protocol": session.findtext('proto', default="N/A"),
                "Start Time": session.findtext('start-time', default="N/A")
            })
        except Exception as e:
            print(f"Error parsing session entry: {e}")

    return session_details, session_count


def display_session_statistics(session_details, session_count):
    """
    Display detailed session information for each active session
    and the session count for each source IP.
    """
    print("\n--- Active Session Details ---")
    for session in session_details:
        for key, value in session.items():
            print(f"{key}: {value}")
        print("-" * 50)

    print("\n--- Active Session Count by Source IP ---")
    for ip, count in session_count.items():
        print(f"Source IP: {ip}, Active Sessions: {count}")
    print("-" * 50)


def main():
    """
    Main loop to fetch, parse, and display session data periodically.
    """
    POLL_INTERVAL = 10  # Time interval in seconds between API calls

    while True:
        session_data = fetch_active_sessions()
        if session_data is not None:
            session_details, session_count = parse_sessions(session_data)
            display_session_statistics(session_details, session_count)
        else:
            print("No session data found or error fetching data.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
