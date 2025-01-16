import requests
import xml.etree.ElementTree as ET
from collections import defaultdict


def fetch_active_sessions(firewall_ip, api_key):
    """
    Fetch the active sessions from the Palo Alto firewall.
    """
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

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
    
def fetch_all_active_sessions(firewall_ip, api_key):
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
    Also track unique source IPs and related zones.
    """
    session_count = defaultdict(int)
    unique_ips = set()
    zone_mapping = {}

    # Find all session entries
    sessions = session_data.findall(".//entry")
    for session in sessions:
        source_ip = session.find('source').text
        src_zone = session.find('from').text
        dst_zone = session.find('to').text

        if source_ip:
            session_count[source_ip] += 1
            unique_ips.add(source_ip)
            zone_mapping[source_ip] = (src_zone, dst_zone)

    return session_count, len(unique_ips), zone_mapping