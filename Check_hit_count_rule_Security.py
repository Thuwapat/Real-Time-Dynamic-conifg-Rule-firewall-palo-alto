import os
import time
import requests
import xml.etree.ElementTree as ET
import urllib.parse

firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings (optional but recommended for testing environments)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
existing_rules = {"DDOSS", "Block_Zone_Trust_to_Untrust"}

import requests
import xml.etree.ElementTree as ET

def get_rule_last_hit_payload(rule_name):
    """
    Fetch the last hit information for a given rule from the Palo Alto firewall
    using a POST request with payload.
    Returns the XML ElementTree root of the API response or an error message.
    """
    # สร้าง XML command สำหรับดึงข้อมูล hit count/last hit time ของ rule
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

    # สร้าง payload สำหรับ POST request
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
            return root  # คืนค่า XML root ของ response
        except ET.ParseError as e:
            return f"XML Parse Error: {e}"
    else:
        return f"HTTP Error: {response.status_code}"
    
    
# def extract_rule_creation_timestamp(xml_root, rule_name):
#     """
#     ดึงค่า <rule-creation-timestamp> จาก XML ที่ส่งกลับมาสำหรับ rule ที่ระบุ
#     """
#     # ตัวอย่าง XML ที่ได้จะมีโครงสร้าง <entry name="rule_name"> ... <rule-creation-timestamp>value</rule-creation-timestamp> ...
#     # เราสามารถใช้ XPath เพื่อตามหา element ที่ต้องการ
#     # หากชื่อ rule ใน XML ไม่ได้เป็น attribute name ของ entry โดยตรง (เช่นในตัวอย่าง XML, entry name="DDOSS")
#     # ให้ปรับ XPath ให้ตรงกับโครงสร้างที่แท้จริง
#     rule_entry = xml_root.find(f".//entry[@name='{rule_name}']")
#     if rule_entry is not None:
#         ts_elem = rule_entry.find("rule-creation-timestamp")
#         if ts_elem is not None:
#             return ts_elem.text
#     return None

# # Loop เพื่อดึงข้อมูลของแต่ละ rule ทุก ๆ 5 วินาที
# while True:
#     print("------ Checking rule creation timestamps ------")
#     for rule in existing_rules:
#         result = get_rule_last_hit_payload(rule)
#         if isinstance(result, ET.Element):
#             timestamp = extract_rule_creation_timestamp(result, rule)
#             if timestamp:
#                 print(f"Rule: {rule} | Rule Creation Timestamp: {timestamp}")
#             else:
#                 print(f"Rule: {rule} | rule-creation-timestamp not found.")
#         else:
#             print(f"Error for rule {rule}:", result)
#     # รอ 5 วินาที ก่อนทำการ query ครั้งถัดไป
#     time.sleep(5)

def delete_rule(rule_name):
    """
    ส่งคำสั่งลบ rule ออกจาก firewall ผ่าน API
    (ตัวอย่างนี้ใช้ XML command deletion ผ่าน XPath ตามที่ API ของ Palo Alto อนุญาต)
    """
    # ตัวอย่าง XML command deletion โดยใช้ xpath
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

def check_and_remove_rule(rule_name):
    """
    ตรวจสอบ last hit time ของ rule หากไม่ได้ถูก hit เป็นเวลาเกิน 60 วินาที (หรือค่าเป็น 0)
    ให้ลบ rule ทั้งใน firewall และจาก existing_rules
    """
    result = get_rule_last_hit_payload(rule_name)
    if isinstance(result, ET.Element):
        # ค้นหาค่า last-hit-timestamp
        ts_elem = result.find(".//last-hit-timestamp")
        if ts_elem is not None:
            try:
                last_hit = int(ts_elem.text)
            except ValueError:
                print(f"Invalid last-hit-timestamp for rule {rule_name}: {ts_elem.text}")
                return
            current_time = int(time.time())
            # หาก last_hit เป็น 0 (ยังไม่มีการ hit) หรือไม่ได้ hit เกิน 60 วินาที
            if  (current_time - last_hit > 60):
                print(f"Rule {rule_name} is inactive for over 60 seconds (last hit: {last_hit}). Deleting rule.")
                # deletion_response = delete_rule(rule_name)
                # print("Deletion response:", deletion_response)
                # ลบ rule จาก existing_rules
                # existing_rules.remove(rule_name)
            else:
                print(f"Rule {rule_name} is active. Last hit time: {last_hit} (current time: {current_time}).")
        else:
<<<<<<< HEAD
            print(f"Error for rule {rule}:", result)
    # รอ 5 วินาที ก่อนทำการ query ครั้งถัดไป
    time.sleep(1)
=======
            print(f"Could not find last-hit-timestamp for rule {rule_name}.")
    else:
        print(f"Error retrieving data for rule {rule_name}: {result}")

# Loop หลัก เพื่อตรวจสอบ rule ทุกๆ 5 วินาที
while True:
    print("------ Checking rules ------")
    # ทำสำเนาของ existing_rules เพื่อป้องกันปัญหาในขณะที่ลูป (เนื่องจากเราจะลบ rule ออก)
    rules_to_check = list(existing_rules)
    for rule in rules_to_check:
        check_and_remove_rule(rule)
    # รอ 5 วินาทีก่อนตรวจสอบรอบต่อไป
    time.sleep(5)
>>>>>>> 50691f55c784f636ae4a3f31157fb0bb71af660f
