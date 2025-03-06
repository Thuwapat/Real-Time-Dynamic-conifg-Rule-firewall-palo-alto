import requests
import xml.etree.ElementTree as ET
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fetch_rule_hit_count(rule_name):
    """
    Fetch the rule hit count for a specific security rule on vsys1.
    """
    url = f"https://{firewall_ip}/api/"
    payload = {
        'type': 'op',
        'key': api_key,
        'cmd': f"""
        <show>
            <rule-hit-count>
                <vsys>
                    <vsys-name>
                        <entry name='vsys1'>
                            <rule-base>
                                <entry name='security'>
                                    <rules>
                                        <list>
                                            <member>{rule_name}</member>
                                        </list>
                                    </rules>
                                </entry>
                            </rule-base>
                        </entry>
                    </vsys-name>
                </vsys>
            </rule-hit-count>
        </show>
        """
    }

    try:
        response = requests.get(url, params=payload, verify=False)
        if response.status_code == 200:
            return parse_rule_hit_count(response.text)
        else:
            print(f"Error fetching rule hit count: HTTP {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching rule hit count: {e}")
        return None


def parse_rule_hit_count(response_xml):
    """
    Parse the XML response and extract the rule hit count.
    """
    try:
        root = ET.fromstring(response_xml)
        hit_count = root.find(".//hit-count").text  # Extract the hit count
        return hit_count
    except Exception as e:
        print(f"Error parsing rule hit count: {e}")
        return None


if __name__ == "__main__":
    # Replace 'Trust-to-Untrust' with the actual rule name you want to check
    rule_name = "trust to untrust"

    hit_count = fetch_rule_hit_count(rule_name)
    if hit_count is not None:
        print(f"Rule '{rule_name}' Hit Count: {hit_count}")
    else:
        print(f"Failed to fetch hit count for rule '{rule_name}'.")
