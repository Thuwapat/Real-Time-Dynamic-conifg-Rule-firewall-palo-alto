import requests
import xml.etree.ElementTree as ET
from collections import defaultdict

def fetch_info_sessions(firewall_ip, api_key):
    """
    Fetch the active sessions from the Palo Alto firewall.
    """
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
    

def parse_act_sessions(actsession_data):
    """
    Parse the active session data and calculate session counts for each source IP.
    Also track unique source IPs and related zones.
    """
    actsession_count = defaultdict(int)
    unique_ips = set()
    zone_mapping = {}

    # Find all session entries
    actsessions = actsession_data.findall(".//entry")
    for actsession in actsessions:
        source_ip = actsession.find('source').text
        src_zone = actsession.find('from').text
        dst_zone = actsession.find('to').text

        if source_ip:
            actsession_count[source_ip] += 1
            unique_ips.add(source_ip)
            zone_mapping[source_ip] = (src_zone, dst_zone)

    return actsession_count, len(unique_ips), zone_mapping

def parse_info_sessions(session_data):
    """
    Parse session statistics for ML-based detection.
    """
    sessions = session_data.findall(".//result")
    for session in sessions:
        cps = session.find('cps').text
        kbps = session.find('kbps').text
        num_active = session.find('num-active').text
        num_icmp = session.find('num-icmp').text
        num_tcp = session.find('num-tcp').text
        num_udp = session.find('num-udp').text
        pps = session.find('pps').text
    return cps, kbps, num_active, num_icmp, num_tcp, num_udp, pps


