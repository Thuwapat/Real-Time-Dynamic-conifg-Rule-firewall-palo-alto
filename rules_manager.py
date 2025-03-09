import os
import time
import requests
import xml.etree.ElementTree as ET
from rules_config_funct import commit_changes

firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

DEFAULT_INACTIVE_THRESHOLD = 120  
SLOWLORIS_INACTIVE_THRESHOLD = 120
CHECK_DELAY = 10  
GRACE_PERIOD = 60

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
        if response.status_code == 200:
            return ET.fromstring(response.text)
        else:
            return f"HTTP Error: {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

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

    if not isinstance(result, ET.Element):
        print(f"Cannot retrieve rule info for {rule_name}: {result}. Skipping.")
        return

    creation_elem = result.find(".//rules/entry/rule-creation-timestamp")
    if creation_elem is None or creation_elem.text is None:
        print(f"Cannot retrieve creation time for {rule_name}. Skipping until creation time is available.")
        return
    creation_time = int(creation_elem.text.strip())

    current_time = int(time.time())
    time_since_creation = current_time - creation_time

    if time_since_creation < GRACE_PERIOD:
        print(f"Rule {rule_name} is within grace period ({time_since_creation}/{GRACE_PERIOD} sec). Skipping removal.")
        return

    ts_elem = result.find(".//rules/entry/last-hit-timestamp")
    last_hit = int(ts_elem.text.strip()) if ts_elem is not None and ts_elem.text is not None else 0
    time_difference = current_time - last_hit if last_hit > 0 else float('inf')

    if "Block_Slowloris" in rule_name:
        inactive_threshold = SLOWLORIS_INACTIVE_THRESHOLD
        rule_type = "Slowloris"
    else:
        inactive_threshold = DEFAULT_INACTIVE_THRESHOLD
        rule_type = "DoS/DDoS"

    #print(f"Debug: Rule {rule_name}, creation_time={creation_time}, last_hit={last_hit}, current_time={current_time}, "
    #      f"time_since_creation={time_since_creation}, time_difference={time_difference}")

    if last_hit == 0 and time_since_creation > inactive_threshold + GRACE_PERIOD:
        print(f"Rule {rule_name} ({rule_type}) has never been hit and is past threshold ({time_since_creation} sec since creation). Deleting rule.")
        delete_rule(rule_name)
        existing_rules.remove(rule_name)
    elif time_difference > inactive_threshold:
        print(f"Rule {rule_name} ({rule_type}) is inactive for over {inactive_threshold} seconds (last hit: {last_hit}). Deleting rule.")
        delete_rule(rule_name)
        existing_rules.remove(rule_name)
    else:
        print(f"Rule {rule_name} ({rule_type}) is active. Last hit time: {last_hit} (current time: {current_time}, diff: {time_difference} sec).")

def sync_existing_rules():
    url = f"https://{firewall_ip}/restapi/v10.2/Policies/DoSRules?location=vsys&vsys=vsys1"
    response = requests.get(url, headers={'X-PAN-KEY': api_key}, verify=False)
    if response.status_code == 200:
        return {rule['@name'] for rule in response.json().get('entry', [])}
    return set()