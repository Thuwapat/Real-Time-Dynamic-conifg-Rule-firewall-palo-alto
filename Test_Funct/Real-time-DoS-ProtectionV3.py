import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
import time
import os 

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
# LINE Bot credentials
LINE_API_URL = "https://api.line.me/v2/bot/message/push"
LINE_ACCESS_TOKEN = "zzyg77lLEwdFNoOML9iGw2Rt8zufx5zBFU5ZceYORa70DLgbPc9AS04a+7W6/mLp8CLoYV0imejR4fGtFEs7VQLyLyLMBtjQgHt7kXMRNcUEGdmXV4OEPtPEMOPcWQDPKbHpTJXTS9eH0cBzROOsPQdB04t89/1O/w1cDnyilFU="  # Replace with your LINE access token
LINE_USER_ID = "U54ed3cb10b1591fd7501976108dc1e36"

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fetch_active_sessions():
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

existing_rules = set() # Global set to track already reported rules

# Function to create a DoS profile using REST API
def create_dos_profile(api_key):
    profile_name = "default-profile"
    url = f"https://{firewall_ip}/restapi/v10.2/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
    headers = {'Content-Type': 'application/json', 'X-PAN-KEY': api_key}

    # Define the rule payload in JSON format
    payload = {
        "entry": {
            "@name": profile_name,
            "type": "aggregate",
            "flood": {
                "tcp-syn": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                },
                "udp": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                },
                "icmp": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                },
                "icmpv6": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                },
                "other-ip": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                }
            },
            "resource": {
                "sessions": {
                    "enabled": "yes"
                }
            },
        }
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        commit_changes()
        print(f"DoS Protection Policy created successfully: {profile_name}")
    elif response.status_code == 409:
        if profile_name not in existing_rules:
                print(f"Policy {profile_name} already exists")
                existing_rules.add(profile_name)
    else:
        print(f"Failed to create DoS Protection Policy: {response.status_code} - {response.text}")

def create_dos_protection_policy(src_ip, src_zone, dst_zone, rule_name):
    """
    Create a DoS Protection Policy for a specific source IP.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {'Content-Type': 'application/json', 'X-PAN-KEY': api_key}

    payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "zone": {
                    "member": [src_zone]
                }
            },
            "to": {
                "zone": {
                    "member": [dst_zone]
                }
            },
            "source": {
                "member": [src_ip]
            },
            "destination": {
                "member": ["any"]
            },
            "service": {
                "member": ["any"]
            },
            "source-user": {
                "member": ["any"]
            },
            "protection": {
                "aggregate": {
                    "profile": "default-profile"
                }
            },
            "action": {
                "deny": {}
            },
        }
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        commit_changes()
        print(f"DoS Protection Policy created successfully: {rule_name}")
        message = (f"🚨 DoS Detected 🚨\n"
                    f"Source IP: {src_ip} \n"
                    f"From: {src_zone} to: {dst_zone}")
        send_line_notification(message)
    elif response.status_code == 409:
        if rule_name not in existing_rules:
                print(f"Policy {rule_name} already exists")
                existing_rules.add(rule_name)
    else:
        print(f"Failed to create DoS Protection Policy: {response.status_code} - {response.text}")


def create_ddos_protection_policy(src_zone, dst_zone, rule_name):
    """
    Create a DoS Protection Policy for a zone-based rule.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {'Content-Type': 'application/json', 'X-PAN-KEY': api_key}

    payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "zone": {
                    "member": [src_zone]
                }
            },
            "to": {
                "zone": {
                    "member": [dst_zone]
                }
            },
            "source": {
                "member": ["any"]
            },
            "destination": {
                "member": ["any"]
            },
            "service": {
                "member": ["any"]
            },
            "source-user": {
                "member": ["any"]
            },
            "protection": {
                "aggregate": {
                    "profile": "default-profile"
                }
            },
            "action": {
                "deny": {}
            },
        }
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        commit_changes()
        print(f"DDoS Protection Policy created successfully: {rule_name}")
        message = (f"🚨 DDoS Detected 🚨\n"
                    f"Create Rules Block Zone\n"
                    f"From: {src_zone} to: {dst_zone}")
        send_line_notification(message)
    elif response.status_code == 409:
        if rule_name not in existing_rules:
                print(f"Policy {rule_name} already exists")
                existing_rules.add(rule_name)
    else:
        print(f"Failed to create DDoS Protection Policy: {response.status_code} - {response.text}")

def commit_changes():
    """
    Commit the changes to the Palo Alto firewall.
    """
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    payload = {
        'type': 'commit',
        'cmd': '<commit></commit>',
        'key': api_key
    }

    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            print("Changes committed successfully.")
        else:
            print(f"Failed to commit changes: HTTP {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error committing changes: {e}")

def send_line_notification(message):
    """
    Send a notification via LINE Chatbot.
    """
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {LINE_ACCESS_TOKEN}'
    }

    payload = {
        "to": LINE_USER_ID,
        "messages": [
            {
                "type": "text",
                "text": message
            }
        ]
    }

    try:
        response = requests.post(LINE_API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            print("Notification sent successfully via LINE.")
        else:
            print(f"Failed to send LINE notification. Response: {response.text}")
    except Exception as e:
        print(f"Error sending LINE notification: {e}")


def main():
    """
    Main loop to fetch sessions, analyze, and create security rules if thresholds are exceeded.
    """
    POLL_INTERVAL = 1  # Time interval in seconds to fetch sessions
    SESSION_THRESHOLD = 20  # Threshold for active session count per Source IP
    UNIQUE_IP_THRESHOLD = 1000  # Threshold for total unique Source IPs

    print("-------- Start Script -----------")
    while True:
        session_data = fetch_active_sessions()
        if session_data is not None:
            session_count, unique_ip_count, zone_mapping = parse_sessions(session_data)

            # Check each Source IP for session threshold
            for src_ip, count in session_count.items():
                if count >= SESSION_THRESHOLD:
                    print(">>>>>>>> DoS Detected !!!!! <<<<<<<<")
                    src_zone, dst_zone = zone_mapping[src_ip]
                    rule_name = f"Block_IP_{src_ip.replace('.', '_')}"
                    create_dos_profile(api_key)
                    create_dos_protection_policy(src_ip, src_zone, dst_zone, rule_name)

            # Check if unique IP count exceeds threshold
            if unique_ip_count >= UNIQUE_IP_THRESHOLD:
                for src_ip, (src_zone, dst_zone) in zone_mapping.items():
                    print(">>>>>>>>> DDoS Detected !!!!!! <<<<<<<<")
                    rule_name = f"Block_Zone_{src_zone}_to_{dst_zone}"
                    create_dos_profile(api_key)
                    create_ddos_protection_policy(src_zone, dst_zone, rule_name)
                    break  # Create one rule for zones (to prevent duplicates)

        else:
            print("No session data found.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
