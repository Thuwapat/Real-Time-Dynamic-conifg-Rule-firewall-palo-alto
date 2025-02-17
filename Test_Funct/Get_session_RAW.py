import requests
import xml.dom.minidom  # For pretty-printing raw XML
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fetch_raw_sessions():
    """
    Fetch the raw session data from the Palo Alto firewall.
    """
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Use the 'type=session' API call to get raw session data
    payload = {
        'type': 'op',
        'cmd': '<show><session><all></all></session></show>',
        'key': api_key
    }

    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return response.text  # Return raw XML data as a string
        else:
            print(f"Error fetching raw session data: HTTP {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching sessions: {e}")
        return None

def pretty_print_raw_data(raw_data):
    """
    Pretty-print the raw XML data for better readability.
    """
    try:
        dom = xml.dom.minidom.parseString(raw_data)
        print(dom.toprettyxml(indent="  "))
    except Exception as e:
        print(f"Error parsing raw XML: {e}")
        print("Raw data:")
        print(raw_data)

if __name__ == "__main__":
    # Main loop to fetch and display raw session data periodically
    POLL_INTERVAL = 10  # Time interval in seconds to fetch sessions

    while True:
        raw_data = fetch_raw_sessions()
        if raw_data:
            print("\n--- Raw Session Data ---")
            pretty_print_raw_data(raw_data)  # Pretty-print the raw XML data
        else:
            print("No raw session data found.")

        time.sleep(POLL_INTERVAL)
