import requests
import xml.etree.ElementTree as ET
import time

# Palo Alto Firewall credentials and IP
firewall_ip = "192.168.15.5"  # Replace with your firewall IP
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="  # Replace with your API key

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_rules(rule_type):
    """
    Fetch the current rules and their hit counts based on rule type.
    """
    url = f"https://{firewall_ip}/api/"
    rule_types = {
        "security": '<show><rule-hit-count><vsys>vsys1</vsys></rule-hit-count></show>',
        "dos-protection": '<show><rule-hit-count><vsys>vsys1</vsys><type>dos-protection</type></rule-hit-count></show>'
    }
    
    if rule_type not in rule_types:
        raise ValueError("Invalid rule type specified. Use 'security' or 'dos-protection'.")

    payload = {
        'type': 'op',
        'cmd': rule_types[rule_type],
        'key': api_key
    }

    try:
        response = requests.post(url, data=payload, verify=False)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return ET.fromstring(response.text)
    except requests.RequestException as e:
        print(f"Error fetching {rule_type} rules: {e}")
        return None


def parse_and_display_rules(rule_data, rule_type):
    """
    Parse and display hit counts for the given rule data.
    """
    print(f"\n--- {rule_type.capitalize()} Rules Hit Counts ---")
    for entry in rule_data.findall(".//entry"):
        rule_name = entry.find('name').text
        hit_count = entry.find('hit-count').text
        print(f"Rule: {rule_name}, Hit Count: {hit_count}")


def display_all_rules():
    """
    Fetch and display hit counts for both Security Rules and DoS Protection Rules.
    """
    for rule_type in ["security", "dos-protection"]:
        rules = get_rules(rule_type)
        if rules is not None:
            parse_and_display_rules(rules, rule_type)
        else:
            print(f"Failed to fetch {rule_type.capitalize()} Rules.")


def main():
    """
    Main function to run display_all_rules in a loop every second.
    """
    try:
        while True:
            display_all_rules()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting program.")


if __name__ == "__main__":
    main()