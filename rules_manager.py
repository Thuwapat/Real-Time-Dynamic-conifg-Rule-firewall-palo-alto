# rules_manager.py
import os
import time
import requests
import xml.etree.ElementTree as ET
import urllib.parse

# ดึงค่า firewall_ip และ api_key จาก environment variable
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

def get_rule_last_hit_payload(rule_name):
    """
    Fetch the hit information for a given rule from the Palo Alto firewall using a POST request with payload.
    Returns the XML ElementTree root of the API response or an error message.
    """
    xml_cmd = f"""
    <show>
      <rule-hit-count>
        <vsys>
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
    """
    ส่งคำสั่งลบ rule ออกจาก firewall ผ่าน API
    (ตัวอย่างนี้ใช้ XML command deletion ผ่าน XPath ตามที่ API ของ Palo Alto อนุญาต)
    """
    xpath = f"/config/devices/entry/vsys/entry/rule-base/entry[@name='dos']/rules/entry[@name='{rule_name}']"
    payload = {
        'type': 'config',
        'action': 'delete',
        'key': api_key,
        'xpath': xpath
    }
    url = f"https://{firewall_ip}/api/"
    try:
        response = requests.post(url, data=payload, verify=False, timeout=10)
    except Exception as e:
        return f"Error during deletion: {e}"
    
    return response.text

def check_and_remove_rule(rule_name, existing_rules):
    """
    ตรวจสอบ last hit time ของ rule หากไม่ได้ถูก hit เป็นเวลาเกิน 60 วินาที (หรือค่าเป็น 0)
    ให้ลบ rule ทั้งใน firewall และจาก existing_rules
    """
    result = get_rule_last_hit_payload(rule_name)
    if isinstance(result, ET.Element):
        ts_elem = result.find(".//last-hit-timestamp")
        if ts_elem is not None:
            try:
                last_hit = int(ts_elem.text)
            except ValueError:
                print(f"Invalid last-hit-timestamp for rule {rule_name}: {ts_elem.text}")
                return
            current_time = int(time.time())
            if last_hit == 0 or (current_time - last_hit > 60):
                print(f"Rule {rule_name} is inactive for over 60 seconds (last hit: {last_hit}). Deleting rule.")
                deletion_response = delete_rule(rule_name)
                print("Deletion response:", deletion_response)
                try:
                    existing_rules.remove(rule_name)
                except KeyError:
                    pass
            else:
                print(f"Rule {rule_name} is active. Last hit time: {last_hit} (current time: {current_time}).")
        else:
            print(f"Could not find last-hit-timestamp for rule {rule_name}.")
    else:
        print(f"Error retrieving data for rule {rule_name}: {result}")
