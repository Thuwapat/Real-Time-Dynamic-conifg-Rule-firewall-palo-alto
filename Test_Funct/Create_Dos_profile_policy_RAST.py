import requests
import json

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.1.100"
api_key = "LUFRPT1zc1Q1VGZpeGNRWGNDbkswdTBUaStHNDdBZWM9TUk0c1htY1YrQVlTd3hvUmtvb1B2SDVqRTdOVHRGK1FuVWtrUksrQVdyckw0MktPSWo0RU1ONldlc0lqR2J3Wg=="
api_key_admin1 = "LUFRPT1za25maERjYlBZM0lGek9JaG1LcE4zMWRUaXc9SU1nK0NKbHJDdnBWY3BPOEFNSzdlckhEbjlvZ2hYT1BhK3BMeUthOFViMVl3ZHc1UDJVVVZXNDg3VHNyYVc0Mg=="
profile_name = "DDoS-Protection"
rule_name = "rule_dos"
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def create_dos_protection_profile():
  url = f"https://{firewall_ip}/restapi/v10.1/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
  headers = {
      'Content-Type': 'application/json',
      'X-PAN-KEY': api_key
  }

  payload = {
      "entry": {
            "@name": profile_name,
            "type": "aggregate",
            "flood": {
                "tcp-syn": {
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                    "enable": "yes"
                },
                "udp": {
                    "red": {
                        "alarm-rate": 10000,
                        "activate-rate": 10000,
                        "maximal-rate": 40000
                    },
                    "enable": "yes"
                       }
                    }
              }
    }
      
  

  response = requests.post(url, headers=headers, json=payload, verify=False)

  if response.status_code == 200:
      print("DoS Protection Profile created successfully.")
  else:
      print(f"Failed to create DoS Protection Profile. Status code: {response.status_code}")
      print(response.text)

def create_dos_protection_policy():
    url = f"https://{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1&name={rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    payload = {
        "entry": {
            "@name": rule_name,
            "from": {
                "zone": {
                    "member": ["WAN-Zone"]
                }
            },
            "to": {
                "zone": {
                    "member": ["LAN-Zone"]
                }
            },
            "source": {
                "member": ["any"]
            },
            "destination": {
                "member": ["any"]
            },
            "service": {
                "member": ["any"]
            },
            "source-user": {
                "member": ["any"]
            },
            "action": {
                "protect": {}
            },
            "protection": {
                "aggregate": {
                    "profile": profile_name,
                }
            }
        }
    }
    response = requests.post(url, headers=headers, json=payload, verify=False)

    if response.status_code == 200:
        print("DoS Protection Policy created successfully.")
    else:
        print(f"Failed to create DoS Protection Policy. Status code: {response.status_code}")
        print(response.text)

def commit_changes():
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    payload = {
        'type': 'commit',
        'cmd': '<commit></commit>',
        'key': api_key_admin1
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        print("Commit successful.")
    else:
        print(f"Failed to commit changes. Status code: {response.status_code}")
        print(response.text)

# Main function to run all steps
def main():
    # print("Creating DoS Protection Profile...")
    # create_dos_protection_profile()
    
    # print("Creating DoS Protection Policy...")
    # create_dos_protection_policy()
    
   print("Committing changes...")
   commit_changes()

# Execute the main function
if __name__ == "__main__":
 main()
