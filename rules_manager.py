# rules_manager.py
import os
import time
import requests
import xml.etree.ElementTree as ET
from rules_config_funct import commit_changes
import urllib.parse

# ดึงค่า firewall_ip และ api_key จาก environment variable
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

def get_rule_last_hit_payload(rule_name):
    """
    Fetch the last hit timestamp for a given rule from the Palo Alto firewall.
    Returns the XML ElementTree root of the API response or an error message.
    """
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
        #print("API Response:", response.text)  # ✅ Debugging output
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
    url = f"{firewall_ip}/restapi/v10.2/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {'X-PAN-KEY': api_key, 'Content-Type': 'application/json'}
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 200:
        commit_changes(firewall_ip, api_key)
        print(f"DoS Rule '{rule_name}' deleted successfully.")
    else:
        print(f"Failed to delete DoS Rule '{rule_name}': {response.status_code} - {response.text}")

def check_and_remove_rule(rule_name, existing_rules):
    """
    ตรวจสอบ last hit time ของ rule หากไม่ได้ถูก hit เป็นเวลาเกิน 60 วินาที (หรือค่าเป็น 0)
    ให้ลบ rule ทั้งใน firewall และจาก existing_rules
    """
    result = get_rule_last_hit_payload(rule_name)

    if isinstance(result, ET.Element):
        ts_elem = result.find(".//rules/entry/last-hit-timestamp")  # ✅ Adjusted XPath
        if ts_elem is not None and ts_elem.text is not None:
            try:
                last_hit = int(ts_elem.text.strip())  # ✅ Ensure clean int conversion
                current_time = int(time.time())
                time_difference = current_time - last_hit

                if last_hit == 0 or time_difference > 10:
                    print(f"Rule {rule_name} is inactive for over 60 seconds (last hit: {last_hit}). Deleting rule.")
                    delete_rule(rule_name)
                    #print("Deletion response:", deletion_response)
                    existing_rules.remove(rule_name)  # ✅ Avoid KeyError
                else:
                    print(f"Rule {rule_name} is active. Last hit time: {last_hit} (current time: {current_time}).")
            except ValueError:
                print(f"Invalid last-hit-timestamp for rule {rule_name}: {ts_elem.text}")
        else:
            print(f"Could not find last-hit-timestamp for rule {rule_name}.")
    else:
        print(f"Error retrieving data for rule {rule_name}: {result}")

