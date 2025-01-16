import requests

# Function to create a DoS profile using REST API
def create_dos_profile(firewall_ip, api_key, existing_rules):
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
        commit_changes(firewall_ip, api_key)
        print(f"DoS Protection Policy created successfully: {profile_name}")
    elif response.status_code == 409:
        if profile_name not in existing_rules:
                print(f"Policy {profile_name} already exists")
                existing_rules.add(profile_name)
    else:
        print(f"Failed to create DoS Protection Policy: {response.status_code} - {response.text}")

def create_dos_protection_policy(firewall_ip, api_key, src_ip, src_zone, dst_zone, rule_name, existing_rules):
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
        commit_changes(firewall_ip, api_key)
        print(f"DoS Protection Policy created successfully: {rule_name}")
        #message = (f"🚨 DoS Detected 🚨\n"
        #            f"Source IP: {src_ip} \n"
        #            f"From: {src_zone} to: {dst_zone}")
        #send_line_notification(message)
    elif response.status_code == 409:
        if rule_name not in existing_rules:
                print(f"Policy {rule_name} already exists")
                existing_rules.add(rule_name)
    else:
        print(f"Failed to create DoS Protection Policy: {response.status_code} - {response.text}")


def create_ddos_protection_policy(firewall_ip, api_key, src_zone, dst_zone, rule_name, existing_rules):
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
        commit_changes(firewall_ip, api_key)
        print(f"DDoS Protection Policy created successfully: {rule_name}")
        #message = (f"🚨 DDoS Detected 🚨\n"
        #            f"Create Rules Block Zone\n"
        #            f"From: {src_zone} to: {dst_zone}")
        #send_line_notification(message)
    elif response.status_code == 409:
        if rule_name not in existing_rules:
                print(f"Policy {rule_name} already exists")
                existing_rules.add(rule_name)
    else:
        print(f"Failed to create DDoS Protection Policy: {response.status_code} - {response.text}")

def commit_changes(firewall_ip, api_key):
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