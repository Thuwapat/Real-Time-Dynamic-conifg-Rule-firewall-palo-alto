import requests
import json

# Palo Alto firewall credentials and IP
firewall_ip = "https://192.168.1.100"
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="

# Disable SSL warnings (not recommended for production)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a DoS rule using REST API
def create_dos_rule(api_key):
    profile_name = "DoS_Profile"
    url = f"{firewall_ip}/restapi/v10.1/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
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
