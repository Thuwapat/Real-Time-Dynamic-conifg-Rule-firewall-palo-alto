import os
import time
import requests
import xml.etree.ElementTree as ET
import urllib.parse

firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

# Disable SSL warnings (optional but recommended for testing environments)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
existing_rules = {"Block_IP_192_168_1_10", "Block_Zone_Trust_to_Untrust"}

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
    
    
def extract_rule_creation_timestamp(xml_root, rule_name):
    """
    ดึงค่า <rule-creation-timestamp> จาก XML ที่ส่งกลับมาสำหรับ rule ที่ระบุ
    """
    # ตัวอย่าง XML ที่ได้จะมีโครงสร้าง <entry name="rule_name"> ... <rule-creation-timestamp>value</rule-creation-timestamp> ...
    # เราสามารถใช้ XPath เพื่อตามหา element ที่ต้องการ
    # หากชื่อ rule ใน XML ไม่ได้เป็น attribute name ของ entry โดยตรง (เช่นในตัวอย่าง XML, entry name="DDOSS")
    # ให้ปรับ XPath ให้ตรงกับโครงสร้างที่แท้จริง
    rule_entry = xml_root.find(f".//entry[@name='{rule_name}']")
    if rule_entry is not None:
        ts_elem = rule_entry.find("rule-creation-timestamp")
        if ts_elem is not None:
            return ts_elem.text
    return None

# Loop เพื่อดึงข้อมูลของแต่ละ rule ทุก ๆ 5 วินาที
while True:
    print("------ Checking rule creation timestamps ------")
    for rule in existing_rules:
        result = get_rule_last_hit_payload(rule)
        if isinstance(result, ET.Element):
            timestamp = extract_rule_creation_timestamp(result, rule)
            if timestamp:
                print(f"Rule: {rule} | Rule Creation Timestamp: {timestamp}")
            else:
                print(f"Rule: {rule} | rule-creation-timestamp not found.")
        else:
            print(f"Error for rule {rule}:", result)
    # รอ 5 วินาที ก่อนทำการ query ครั้งถัดไป
    time.sleep(5)