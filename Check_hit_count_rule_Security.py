import requests
import xml.etree.ElementTree as ET
import time

# Palo Alto Firewall credentials and IP
firewall_ip = "192.168.15.5"  # Replace with your firewall IP
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="  # Replace with your API key

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def get_security_rules():
    """
    Fetch the Security Rules and their hit counts.
    """
    url = f"https://{firewall_ip}/api/"
    payload = {
        'type': 'op',
        # 'cmd': '<show><rule-hit-count><vsys>vsys1</vsys></rule-hit-count></show>',
        'cmd': '<show><rule-hit-count></rule-hit-count></show>',
        'key': api_key
    }

    try:
        response = requests.post(url, data=payload, verify=False)
        if response.status_code == 200:
            return ET.fromstring(response.text)
        else:
            print(f"Error fetching Security Rules: HTTP {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching Security Rules: {e}")
        return None

def parse_and_display_security_rules(rule_data):
    """
    Parse and display hit counts for Security Rules.
    """
    print("\n--- Security Rules Hit Counts ---")
    for entry in rule_data.findall(".//entry"):
        rule_name = entry.find('name').text
        hit_count = entry.find('hit-count').text
        print(f"Rule: {rule_name}, Hit Count: {hit_count}")

def main():
    """
    Main function to fetch and display Security Rules hit counts every second.
    """
    try:
        while True:
            security_rules = get_security_rules()
            if security_rules is not None:
                parse_and_display_security_rules(security_rules)
            else:
                print("Failed to fetch Security Rules.")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting program.")

if __name__ == "__main__":
    main()
