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
        response.raise_for_status()
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


def filter_sessions_by_count(session_details, session_count, threshold=10):
    """
    Filter session details for Source IPs that have active session counts greater than the threshold.
    """
    filtered_sessions = [session for session in session_details if session_count[session["Source IP"]] > threshold]
    return filtered_sessions


def display_filtered_sessions(filtered_sessions):
    """
    Display the filtered session details.
    """
    print("\n--- Filtered Active Session Details (Session Count > 10) ---")
    for session in filtered_sessions:
        print(f"Source IP: {session['Source IP']}")
        print(f"Destination IP: {session['Destination IP']}")
        print(f"Src Zone: {session['Src Zone']}")
        print(f"Dst Zone: {session['Dst Zone']}")
        print(f"Source Port: {session['Source Port']}")
        print(f"Destination Port: {session['Destination Port']}")
        print(f"Application: {session['Application']}")
        print(f"Protocol: {session['Protocol']}")
        print(f"Start Time: {session['Start Time']}")
        print("-" * 50)


def main():
    """
    Main loop to fetch, parse, and display filtered session details periodically.
    """
    POLL_INTERVAL = 1  # Time interval in seconds between API calls

    while True:
        session_data = fetch_active_sessions()
        if session_data is not None:
            session_details, session_count = parse_sessions(session_data)
            filtered_sessions = filter_sessions_by_count(session_details, session_count, threshold=10)
            display_filtered_sessions(filtered_sessions)
        else:
            print("No session data found or error fetching data.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
