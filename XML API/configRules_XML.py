import requests
import xml.etree.ElementTree as ET

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.1.100"
username = "user1-api"
password = "admin123456"
api_key = "LUFRPT1qODNlN290SGl3cFhuWDVsWGhPYmN6ckVWWGs9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhna2pqMXlZSW1aVzdJWkNQcUtVUXlHdg=="  # You can generate an API key from the Palo Alto GUI

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Function to create a security rule
def create_security_rule(api_key):
    url = f"https://{firewall_ip}/api/"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Define the XPath and the rule parameters
    xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules"
    rule_name = "Block-YouTube"
    rule_parameters = {
        'from': 'LAN-Zone',
        'to': 'WAN-Zone',
        'source': {
            'member': 'any'
        },
        'destination': {
            'member': 'any'
        },
        'application': {
            'member': 'youtube-base'
        },
        'service': {
            'member': 'application-default'
        },
        'action': 'deny'
    }
    
    # Construct the rule XML
    rule_xml = f"""
    <entry name="{rule_name}">
        <from><member>{rule_parameters['from']}</member></from>
        <to><member>{rule_parameters['to']}</member></to>
        <source><member>{rule_parameters['source']['member']}</member></source>
        <destination><member>{rule_parameters['destination']['member']}</member></destination>
        <application><member>{rule_parameters['application']['member']}</member></application>
        <service><member>{rule_parameters['service']['member']}</member></service>
        <action>{rule_parameters['action']}</action>
    </entry>
    """
    
    # Payload
    payload = {
        'type': 'config',
        'action': 'set',
        'xpath': xpath,
        'element': rule_xml,
        'key': api_key
    }

    # Send the API request
    response = requests.post(url, headers=headers, data=payload, verify=False)

    # Check the response
    if response.status_code == 200:
        response_xml = ET.fromstring(response.text)
        if response_xml.attrib['status'] == 'success':
            print("Rule created successfully.")
        else:
            print(f"Failed to create rule: {response_xml.find('.//msg').text}")
    else:
        print(f"HTTP error: {response.status_code} - {response.text}")

    # Function to commit changes  

if __name__ == "__main__":
    create_security_rule(api_key)