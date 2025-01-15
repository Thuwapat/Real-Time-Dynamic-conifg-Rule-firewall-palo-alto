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
    Also track unique source IPs and related zones.
    """
    session_count = defaultdict(int)
    unique_ips = set()  # Use a set to track unique Source IPs
    zone_mapping = {}  # Track Source Zone and Destination Zone for each Source IP

    # Find all session entries
    sessions = session_data.findall(".//entry")

    for session in sessions:
        source_ip = session.find('source').text  # Extract source IP
        src_zone = session.find('from').text  # Source Zone
        dst_zone = session.find('to').text  # Destination Zone

        if source_ip:
            session_count[source_ip] += 1
            unique_ips.add(source_ip)
            zone_mapping[source_ip] = (src_zone, dst_zone)  # Map zones for the Source IP

    return session_count, len(unique_ips), zone_mapping

existing_rules = set() # Global set to track already reported rules

def create_security_rule_block_ip(rule_name, src_ip):
    """
    Create a Security Rule to block traffic from a specific Source IP using the REST API.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/SecurityRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    # Construct the JSON payload
    payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "member": ["any"]
            },
            "to": {
                "member": ["any"]
            },
            "source": {
                "member": [src_ip]
            },
            "source-user": {
                "member": ["any"]
            },
            "destination": {
                "member": ["any"]
            },
            "service": {
                "member": ["any"]
            },
            "category": {
                "member": ["any"]
            },
            "application": {
                "member": ["any"]
            },
            "action": "deny",
            "description": f"Blocking traffic from Source IP {src_ip}",
            "log-start": "yes",
            "log-end": "yes"
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            print(f"Successfully created Security Rule to block Source IP: {src_ip}")
            move_rule_to_top(rule_name)
        elif response.status_code == 409:
            if rule_name not in existing_rules:
                print(f"Security Rule {rule_name} already exists")
                existing_rules.add(rule_name)
        else:
            print(f"Failed to create Security Rule for Source IP {src_ip}. Response: {response.text}")
    except Exception as e:
        print(f"Error creating Security Rule for Source IP {src_ip}: {e}")




def create_security_rule_block_zone(rule_name, src_zone, dst_zone):
    """
    Create a Security Rule to block traffic between Source Zone and Destination Zone using the REST API.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/SecurityRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    # Construct the JSON payload
    payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "member": [src_zone]
            },
            "to": {
                "member": [dst_zone]
            },
            "source": {
                "member": ["any"]
            },
            "source-user": {
                "member": ["any"]
            },
            "destination": {
                "member": ["any"]
            },
            "service": {
                "member": ["any"]
            },
            "category": {
                "member": ["any"]
            },
            "application": {
                "member": ["any"]
            },
            "action": "deny",
            "description": f"Blocking traffic from Zone {src_zone} to Zone {dst_zone}",
            "log-start": "yes",
            "log-end": "yes"
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            print(f"Successfully created Security Rule to block traffic from Zone: {src_zone} to Zone: {dst_zone}")
            move_rule_to_top(rule_name)
        elif response.status_code == 409:
            if rule_name not in existing_rules:
                print(f"Security Rule {rule_name} already exists")
                existing_rules.add(rule_name)   
        else:
            print(f"Failed to create Security Rule for Zones {src_zone} -> {dst_zone}. Response: {response.text}")
    except Exception as e:
        print(f"Error creating Security Rule for Zones {src_zone} -> {dst_zone}: {e}")

def move_rule_to_top(rule_name):
    """
    Move the specified Security Rule to the top of the rulebase.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/SecurityRules:move?location=vsys&vsys=vsys1&where=top&name={rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    payload = {

    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            print(f"Successfully moved Security Rule {rule_name} to the top of the rulebase")
        else:
            print(f"Failed to move Security Rule {rule_name} to the top. Response: {response.text}")
    except Exception as e:
        print(f"Error moving Security Rule {rule_name} to the top: {e}")

def main():
    """
    Main loop to fetch sessions, analyze, and create security rules if thresholds are exceeded.
    """
    POLL_INTERVAL = 1  # Time interval in seconds to fetch sessions
    SESSION_THRESHOLD = 1000  # Threshold for active session count per Source IP
    UNIQUE_IP_THRESHOLD = 1000  # Threshold for total unique Source IPs

    print("-------- Start Script -----------")
    while True:
        session_data = fetch_active_sessions()
        if session_data is not None:
            session_count, unique_ip_count, zone_mapping = parse_sessions(session_data)

            # Check each Source IP for session threshold
            for src_ip, count in session_count.items():
                if count >= SESSION_THRESHOLD:
                    print(">>>>>>>> DoS Decteced !!!!! <<<<<<<<")
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                    create_security_rule_block_ip(rule_name, src_ip)

            # Check if unique IP count exceeds threshold
            if unique_ip_count >= UNIQUE_IP_THRESHOLD:
                for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                    print(">>>>>>>>> DDoS Decteced !!!!!! <<<<<<<<")
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    create_security_rule_block_zone(rule_name, src_zone, dst_zone)
                    break  # Create one rule for zones (to prevent duplicates)

        else:
            print("No session data found.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
