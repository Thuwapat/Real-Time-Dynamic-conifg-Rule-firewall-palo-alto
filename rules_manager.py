import os
import time
import requests
import xml.etree.ElementTree as ET
from rules_config_funct import commit_changes
import urllib.parse

# ดึงค่า firewall_ip และ api_key จาก environment variable
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

DEFAULT_INACTIVE_THRESHOLD = 10  
SLOWLORIS_INACTIVE_THRESHOLD = 60  

def get_rule_last_hit_payload(rule_name):
    xml_cmd = f"""
    <show>
      <rule-hit-count>
        <vsys>
          <vsys-name>
            <entry name='vsys1'>
              <rule-base>
                <entry name='dos'>
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
    """.strip()

    payload = {
        'type': 'op',
        'key': api_key,
        'cmd': xml_cmd
    }

    url = f"https://{firewall_ip}/api/"
    try:
        response = requests.post(url, data=payload, verify=False, timeout=10)
    except Exception as e:
        return f"Error: {e}"

    if response.status_code == 200:
        try:
            root = ET.fromstring(response.text)
            return root
        except ET.ParseError as e:
            return f"XML Parse Error: {e}"
    else:
        return f"HTTP Error: {response.status_code}"

def delete_rule(rule_name):
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {'X-PAN-KEY': api_key, 'Content-Type': 'application/json'}
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 200:
        commit_changes(firewall_ip, api_key)
        print(f"DoS Rule '{rule_name}' deleted successfully.")
    else:
        print(f"Failed to delete DoS Rule '{rule_name}': {response.status_code} - {response.text}")

def check_and_remove_rule(rule_name, existing_rules):
    result = get_rule_last_hit_payload(rule_name)

    if isinstance(result, ET.Element):
        ts_elem = result.find(".//rules/entry/last-hit-timestamp")
        if ts_elem is not None and ts_elem.text is not None:
            try:
                last_hit = int(ts_elem.text.strip())
                current_time = int(time.time())
                time_difference = current_time - last_hit

                # กำหนด threshold ตามประเภทของ Rule
                if "Block_Slowloris" in rule_name:
                    inactive_threshold = SLOWLORIS_INACTIVE_THRESHOLD
                    rule_type = "Slowloris"
                else:
                    inactive_threshold = DEFAULT_INACTIVE_THRESHOLD
                    rule_type = "DoS/DDoS"

                if last_hit == 0 or time_difference > inactive_threshold:
                    print(f"Rule {rule_name} ({rule_type}) is inactive for over {inactive_threshold} seconds (last hit: {last_hit}). Deleting rule.")
                    delete_rule(rule_name)
                    existing_rules.discard(rule_name)
                else:
                    print(f"Rule {rule_name} ({rule_type}) is active. Last hit time: {last_hit} (current time: {current_time}, diff: {time_difference} sec).")
            except ValueError:
                print(f"Invalid last-hit-timestamp for rule {rule_name}: {ts_elem.text}")
        else:
            print(f"Could not find last-hit-timestamp for rule {rule_name}. Please wait.. Rules is pending.....")
    else:
        print(f"Error retrieving data for rule {rule_name}: {result}")