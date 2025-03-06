import requests
import xml.etree.ElementTree as ET
from collections import defaultdict

# Fetch the sessions info from the Palo Alto firewall.
def fetch_info_sessions(firewall_ip, api_key):
 
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    payload = {
        'type': 'op',
        "cmd": "<show><session><info></info></session></show>",
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

# Fetch the active sessions info from the Palo Alto firewall.
def fetch_active_sessions(firewall_ip, api_key):
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
    
# Parse the active session data and calculate session counts for each source IP.
# Also track unique source IPs and related zones.
def parse_act_sessions(actsession_data):
    actsession_count = defaultdict(int)
    unique_source_ips = set()
    zone_mapping = {}

    # Find all session entries
    actsessions = actsession_data.findall(".//entry")
    for actsession in actsessions:
        source_ip = actsession.find('source').text
        src_zone = actsession.find('from').text
        dst_zone = actsession.find('to').text

        if source_ip and src_zone and dst_zone: 
            actsession_count[source_ip] += 1 
            unique_source_ips.add(source_ip)
            if source_ip not in zone_mapping:
                zone_mapping[source_ip] = (src_zone, dst_zone)
            
    return actsession_count, len(unique_source_ips), zone_mapping

# Parse session statistics for ML-based detection.
def parse_info_sessions(session_data):
    sessions = session_data.findall(".//result")
    for session in sessions:
        cps = int(session.find('cps').text)
        kbps = int(session.find('kbps').text)
        num_active = int(session.find('num-active').text)
        num_icmp = int(session.find('num-icmp').text)
        num_tcp = int(session.find('num-tcp').text)
        num_udp = int(session.find('num-udp').text)
        pps = int(session.find('pps').text)
    return cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps

def clear_sessions(firewall_ip, api_key, src_ip):
    xml_cmd = f"""
    <clear>
      <session>
        <all>
          <filter>
            <source>{src_ip}</source>
          </filter>
        </all>
      </session>
    </clear>
    """.strip()
    
    url = f"https://{firewall_ip}/api/"
    payload = {
        'type': 'op',
        'key': api_key,
        'cmd': xml_cmd
    }
    try:
        response = requests.post(url, data=payload, verify=False, timeout=10)
        if response.status_code == 200:
            print(f"Cleared sessions for {src_ip}")
            return True
        else:
            print(f"Failed to clear sessions for {src_ip}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error clearing sessions for {src_ip}: {e}")
        return False
