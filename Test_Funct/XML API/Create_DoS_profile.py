import requests
import xml.etree.ElementTree as ET
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a DoS rule
def create_dos_rule(api_key):
    url = f"https://{firewall_ip}/api/"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Define the XPath for DoS rule
    xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/profiles/dos-protection"
    rule_name = "DoS-Protect-Profile"
    
    # Construct XML payload without from/to/application parameters
    xml_data = f"""
    <entry name="{rule_name}">
        <flood>
            <tcp-syn>
                <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                    <maximal-rate>40000</maximal-rate>
                </red>
                <enable>yes</enable>
            </tcp-syn>
            <udp>
                <red>
                    <maximal-rate>40000</maximal-rate>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                </red>
                <enable>yes</enable>
            </udp>
            <icmp>
                <red>
                    <maximal-rate>40000</maximal-rate>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                </red>
                <enable>yes</enable>
            </icmp>
            <icmpv6>
                <red>
                    <maximal-rate>40000</maximal-rate>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                </red>
                <enable>yes</enable>
            </icmpv6>
            <other-ip>
                <red>
                    <maximal-rate>40000</maximal-rate>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>10000</activate-rate>
                </red>
                <enable>yes</enable>
            </other-ip>
        </flood>
        <resource>
            <sessions>
                <enabled>yes</enabled>
            </sessions>
        </resource>
        <type>aggregate</type>
    </entry>
    """

    payload = {
        'type': 'config',
        'action': 'set',
        'key': api_key,
        'xpath': xpath,
        'element': xml_data
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    # Print the entire response for debugging purposes
    print("Response Status Code:", response.status_code)
    print("Response Content:", response.content.decode())

    if response.status_code == 200:
        response_xml = ET.fromstring(response.content)
        result = response_xml.find('result')
        if result is not None:
            if result.text.strip() == 'OK':
                print("DoS rule created successfully.")
            else:
                print("DoS rule creation failed. Result:", result.text)
        else:
            print("No result element found in the response. Full response:", response.content.decode())
    else:
        print(f"Failed to create DoS rule. Status code: {response.status_code}, Response: {response.content.decode()}")

# Create the DoS rule
create_dos_rule(api_key)
