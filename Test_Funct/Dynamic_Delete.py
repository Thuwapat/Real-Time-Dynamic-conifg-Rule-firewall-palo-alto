import requests
import json
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to fetch all DoS rules and store values in variables
def fetch_dos_rules(api_key):
    firewall_ip = "https://192.168.11.100"
    url = f"{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }

    # Send the GET request
    response = requests.get(url, headers=headers, verify=False)

    # Check if the response is successful (status code 200)
    if response.status_code == 200:
        try:
            # Parse the response content
            response_data = response.json()
            # Access the top-level "result" key
            result = response_data.get("result", {})

            # Extract individual fields from "entry" under "result" and store them in variables
            dos_rules = result.get("entry", [])

            return dos_rules
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            return None
    else:
        print(f"Failed to fetch DoS rules: {response.status_code} - {response.text}")
        return None

# Function to delete a DoS rule
def delete_dos_rule(api_key, rule_name):
    url = f"{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"DoS Rule '{rule_name}' deleted successfully.")
    else:
        print(f"Failed to delete DoS Rule '{rule_name}': {response.status_code} - {response.text}")

# Function to delete a DoS profile
def delete_dos_profile(api_key, profile_name):
    url = f"{firewall_ip}/restapi/v10.1/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"DoS Profile '{profile_name}' deleted successfully.")
    else:
        print(f"Failed to delete DoS Profile '{profile_name}': {response.status_code} - {response.text}")

# Main function to check and delete unused DoS rules
def check_and_delete_unused_rules(api_key):
    dos_rules = fetch_dos_rules(api_key)
    if dos_rules:
        for rule in dos_rules:
            rule_name = rule["@name"]
            profile_name = rule.get("protection", {}).get("aggregate", {}).get("profile")
            print(f"Deleting DoS Rule '{rule_name}'.....")
            delete_dos_rule(api_key, rule_name)
            print(f"Deleting associated DoS Profile '{profile_name}' for rule '{rule_name}'.......")
            delete_dos_profile(api_key, profile_name)

# Schedule the recheck 
def start_monitoring(api_key):
    print("!!!Start Deleting Unused rule every 5 min!!!")
    while True:
        time.sleep(10)
        print("Rechecking all DoS rules...")
        check_and_delete_unused_rules(api_key)

start_monitoring(api_key)
