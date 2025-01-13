import requests
import json

# Palo Alto firewall credentials and IP
firewall_ip = "https://192.168.15.5"
api_key = "LUFRPT1MNHgrYlFXcVc1bTYxa0F6TUNwZHdqL2lhaGM9cGRQSGNpeTFDWVA4cnlKcUFnaEQzaERMWVJyOWtVcnNuK3NVUWRSQ1MvVkFLYjJ1UXUxQ3ZCOHBrb25PU0hLeA=="

# Disable SSL warnings (not recommended for production)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a DoS rule using REST API
def create_dos_rule(api_key):
    rule_name = "DoS_Protect_Rule"
    dos_profile = "DoS_Profile"
    url = f"{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }

    # Define the rule payload in JSON format
    rule_payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "zone": {
                    "member": ["WAN-Zone"]
                }
            },
            "to": {
                "zone": {
                    "member": ["LAN-Zone"]
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
            "action": {
                "protect": {}
            },
            "protection": {
                "aggregate": {
                    "profile": dos_profile,
                }
            }
        }
    }
        

    # Send the API request to create the rule
    response = requests.post(url, headers=headers, data=json.dumps(rule_payload), verify=False)

    # Check the response
    if response.status_code == 200:
        print("DoS Rule created successfully.")
    else:
        print(f"Failed to create rule: {response.status_code} - {response.text}")

# Create the DoS rule
create_dos_rule(api_key)
