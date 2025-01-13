import requests
import json
import time
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET


firewall_ip = "https://192.168.1.100"
api_key = "LUFRPT1zc1Q1VGZpeGNRWGNDbkswdTBUaStHNDdBZWM9TUk0c1htY1YrQVlTd3hvUmtvb1B2SDVqRTdOVHRGK1FuVWtrUksrQVdyckw0MktPSWo0RU1ONldlc0lqR2J3Wg=="

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to fetch all DoS rules
def fetch_dos_rules(api_key):
    url = f"{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1"
    headers = {
        'X-PAN-KEY': api_key,
        'Content-Type': 'application/json'
    }

    # Send the GET request
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        try:
            # Parse the response content
            response_data = response.json()
            result = response_data.get("result", {})
            dos_rules = result.get("entry", [])

            return dos_rules
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            return None
    else:
        print(f"Failed to fetch DoS rules: {response.status_code} - {response.text}")
        return None

# Function to get the last hit time of a DoS rule
def get_dos_rule_last_hit_time(api_key, rule_name):
    url = f"{firewall_ip}/api/"
    params = {
        'type': 'op',
        'cmd': f'<show><running><rule-hit-count><rule-type>dos</rule-type><vsys>vsys1</vsys><rule-name>{rule_name}</rule-name></rule-hit-count></running></show>',
        'key': api_key
    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        try:
            # Parse XML response
            root = ET.fromstring(response.text)
            status = root.attrib.get('status')
            if status == 'success':
                last_hit_time_str = root.find('.//entry/last-hit-timestamp').text
                # Convert to datetime object
                last_hit_time = datetime.strptime(last_hit_time_str, '%Y/%m/%d %H:%M:%S')
                return last_hit_time
            else:
                print(f"Failed to get last hit time for rule '{rule_name}'.")
                return None
        except Exception as e:
            print(f"Error parsing XML response: {e}")
            return None
    else:
        print(f"Failed to get last hit time: {response.status_code} - {response.text}")
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

# Main function to check and delete DoS rules based on last-hit-time
def check_and_delete_dos_rules(api_key):
    dos_rules = fetch_dos_rules(api_key)
    if dos_rules:
        for rule in dos_rules:
            rule_name = rule["@name"]
            
            profile_name = rule.get("protection", {}).get("aggregate", {}).get("profile")
            # Get the last hit time of the rule
            last_hit_time = get_dos_rule_last_hit_time(api_key, rule_name)
            if last_hit_time:
                # Add 10 minutes to last hit time
                last_hit_plus_10 = last_hit_time + timedelta(minutes=10)
                current_time = datetime.now()
                # If last hit time + 10 minutes is less than current time, delete the rule and profile
                if last_hit_plus_10 <= current_time:
                    print(f"Deleting DoS Rule '{rule_name}' and associated profile '{profile_name}' due to inactivity.")
                    delete_dos_rule(api_key, rule_name)
                    if profile_name:
                        delete_dos_profile(api_key, profile_name)
                else:
                    print(f"DoS Rule '{rule_name}' is still active. Last hit time plus 10 minutes has not passed.")
            else:
                print(f"No last hit time available for DoS Rule '{rule_name}'.") 
    else:
        print("No DoS rules found.")
        
        
def start_monitoring(api_key):
    while True:
        print("Rechecking all DoS rules...")
        check_and_delete_dos_rules(api_key)
        time.sleep(30)

if __name__ == "__main__":
   start_monitoring(api_key)
