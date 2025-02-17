import os
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

# ตัวอย่างการใช้งาน
result = get_rule_last_hit_payload("DDOSS")
if isinstance(result, ET.Element):
    print("Rule hit information fetched successfully (using POST payload).")
    ET.dump(result)  # แสดงข้อมูล XML ทั้งหมด
else:
    print("Error occurred:", result)
