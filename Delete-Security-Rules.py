import requests
import xml.etree.ElementTree as ET
import time
import os

# Palo Alto Firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

#get hit count rule
def get_security_rules():
    """
    Fetch the current security rules and their hit counts.
    """
    url = f"https://{firewall_ip}/api/"
    payload = {
        'type': 'op',
        'cmd': '<show><rule-hit-count><vsys>vsys1</vsys></rule-hit-count></show>',
        'key': api_key
    }

    try:
        response = requests.post(url, data=payload, verify=False)
        if response.status_code == 200:
            return ET.fromstring(response.text)
        else:
            print(f"Error fetching rules: HTTP {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching security rules: {e}")
        return None

def parse_unused_rules(rule_data):
    """
    Parse security rules and track rules with hit count = 0.
    """
    global zero_hit_rules
    current_time = time.time()
    new_zero_hit_rules = {}

    for entry in rule_data.findall(".//entry"):
        rule_name = entry.find('name').text
        hit_count = int(entry.find('hit-count').text)

        if hit_count == 0:
            # If the rule was already tracked, keep the original timestamp
            if rule_name in zero_hit_rules:
                new_zero_hit_rules[rule_name] = zero_hit_rules[rule_name]
            else:
                # Record the current time as the start time for the zero hit count
                new_zero_hit_rules[rule_name] = current_time

    # Update zero_hit_rules to keep only the rules that still have hit-count = 0
    zero_hit_rules = new_zero_hit_rules

    return zero_hit_rules

def delete_security_rule(rule_name):
    """
    Delete a security rule by name using REST API.
    """
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/SecurityRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    try:
        response = requests.delete(url, headers=headers, verify=False)
        if response.status_code == 200:
            print(f"Successfully deleted Security Rule: {rule_name}")
        else:
            print(f"Failed to delete Security Rule {rule_name}. Response: {response.text}")
    except Exception as e:
        print(f"Error deleting Security Rule {rule_name}: {e}")

def main():
    """
    Main function to fetch rules, track unused ones, and delete them after 360 seconds.
    """
    DELETE_THRESHOLD = 5000  # Time in seconds after which the rule will be deleted
    POLL_INTERVAL = 1  # Polling interval in seconds

    print("Starting to monitor security rules...")
    while True:
        rule_data = get_security_rules()
        if rule_data is not None:
            unused_rules = parse_unused_rules(rule_data)

            # Check each rule and delete if the threshold time is exceeded
            for rule_name, start_time in unused_rules.items():
                elapsed_time = time.time() - start_time
                if elapsed_time >= DELETE_THRESHOLD:
                    print(f"Deleting rule {rule_name} - unused for {elapsed_time} seconds")
                    delete_security_rule(rule_name)
                    # Remove the rule from tracking after deletion
                    del zero_hit_rules[rule_name]

        else:
            print("Failed to retrieve rules. Skipping this cycle.")

        # Wait for the next polling interval
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()