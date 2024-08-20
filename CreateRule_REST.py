import requests
import json

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.1.100"
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a security rule using REST API
def create_security_rule(api_key):
    rule_name = "Block-YouTube"
    url = f"https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }

    # Define the rule parameters
    rule_parameters = {
        "entry": {
            "@name": rule_name,
            "from": {
                "member": ["LAN-Zone"]
            },
            "to": {
                "member": ["WAN-Zone"]
            },
            "source": {
                "member": ["any"]
            },
            "destination": {
                "member": ["any"]
            },
            "application": {
                "member": ["youtube-base"]
            },
            "service": {
                "member": ["application-default"]
            },
            "action": "deny"
        }
    }

    # Send the API request
    response = requests.post(url, headers=headers, data=json.dumps(rule_parameters), verify=False)

    # Check the response
    if response.status_code == 200:
        print("Rule created successfully.")
    else:
        print(f"Failed to create rule: {response.status_code} - {response.text}")

if __name__ == "__main__":
    create_security_rule(api_key)
