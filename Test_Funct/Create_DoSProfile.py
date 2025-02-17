import requests
import json
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings 
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a DoS rule using REST API
def create_dos_rule(api_key):
    profile_name = "default-profile"
    url = f"{firewall_ip}/restapi/v10.2/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }

    # Define the rule payload in JSON format
    rule_payload = {
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

    # Send the API request to create the rule
    response = requests.post(url, headers=headers, data=json.dumps(rule_payload), verify=False)

    # Check the response
    if response.status_code == 200:
        print("Profile created successfully.")
    else:
        print(f"Failed to create rule: {response.status_code} - {response.text}")

# Create the DoS rule
create_dos_rule(api_key)
