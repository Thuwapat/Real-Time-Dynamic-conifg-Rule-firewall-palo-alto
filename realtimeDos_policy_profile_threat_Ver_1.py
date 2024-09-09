import requests
import json
import xml.etree.ElementTree as ET
import time

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.1.100"
api_key = "LUFRPT1zc1Q1VGZpeGNRWGNDbkswdTBUaStHNDdBZWM9TUk0c1htY1YrQVlTd3hvUmtvb1B2SDVqRTdOVHRGK1FuVWtrUksrQVdyckw0MktPSWo0RU1ONldlc0lqR2J3Wg=="
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

#################################### API INITIAL SECTION ##############################
def get_job_result(api_key, job_id):
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    payload = {
        'type': 'log',
        'action': 'get',
        'key': api_key,
        'job-id': job_id
    }

    while True:
        response = requests.post(url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            response_xml = ET.fromstring(response.text)
            status = response_xml.attrib.get('status')
            result = response_xml.find('.//result')
            if status == 'success':
                if result is not None:
                    job_status = result.find('job').find('status').text
                    if job_status == 'FIN':
                        logs = result.find('.//logs').findall('entry')
                        log_list = []
                        for log in logs:
                            log_dict = {child.tag: child.text for child in log}
                            # Add the log dictionary to the list
                            log_list.append(log_dict)
                        return log_list
                    elif job_status in ('ACT', 'PEND'):
                        print("Job is still processing. Waiting...")
                        time.sleep(5)
                    else:
                        print(f"Job failed with status: {job_status}")
                        break
            else:
                print(f"Failed to get job status: {response_xml.find('.//msg').text}")
                break
        else:
            print(f"HTTP error: {response.status_code} - {response.text}")
            break
    return None

##################################################################

def get_new_logs(api_key, log_type="threat", last_seqno=None, max_logs=1):
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    query = ""
    if last_seqno:
        query = f"(seqno geq {last_seqno})"  # Only fetch logs with seqno greater than the last one

    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'query': query,
        'nlogs': max_logs
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        try:
            response_xml = ET.fromstring(response.text)
            if response_xml.attrib['status'] == 'success':
                job_id = response_xml.find('.//job').text
                return get_job_result(api_key, job_id)
            else:
                print(f"Failed to retrieve logs: {response_xml.find('.//msg').text}")
        except ET.ParseError as e:
            print(f"Failed to parse response XML: {e}")
            print("Response content:")
            print(response.text)
    else:
        print(f"HTTP error: {response.status_code} - {response.text}")
    return None

def create_dos_protection_profile(threat_type, protocol_type, profile_name):
    url = f"https://{firewall_ip}/restapi/v10.1/Objects/DoSProtectionSecurityProfiles?location=vsys&vsys=vsys1&name={profile_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    payload = {
        "entry": {
            "@name": profile_name,
            "type": "aggregate",
            threat_type: {
                protocol_type: {
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
        print("DoS Protection Profile created successfully. profile : "+ profile_name)
    else:
        print(f"Failed to create DoS Protection Profile. Status code: {response.status_code}")
        print(response.text)

def create_dos_protection_policy(src_ip, src_zone, profile_name,policy_rule_name):
   # policy_rule_name = f"rule_dos_block_{src_ip}"
    url = f"https://{firewall_ip}/restapi/v10.1/Policies/DoSRules?location=vsys&vsys=vsys1&name={policy_rule_name}"
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': api_key
    }

    payload = {
        "entry": {
            "@name": policy_rule_name,
            "from": {
                "zone": {
                    "member": [src_zone]
                }
            },
            "to": {
                "zone": {
                    "member": ["LAN-Zone"]
                }
            },
            "source": {
                "member": [src_ip]
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
        print("DoS Protection Policy created successfully. policy : "+ policy_rule_name)
    elif  response.status_code == 409 :
        print("DoS Protection Policy object already exits")
    else:
        print(f"Failed to create DoS Protection Policy. Status code: {response.status_code}")
        print(response.text)

def poll_logs(api_key, interval=1):
    last_seqno = None
    last_threat = None
    while True:
        logs = get_new_logs(api_key, last_seqno=last_seqno)
        if logs:
            for log in logs:
                current_seqno = int(log['seqno'])
                if last_seqno is None or current_seqno > last_seqno:
                    src_ip = log.get('src')
                    dst_ip = log.get('dst')
                    src_zone = log.get('from')
                    threat_type = log.get('subtype')
                    protocol_type = log.get('proto')

                    current_threat = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_zone': src_zone,
                        'threat_type': threat_type,
                        'protocol_type': protocol_type
                    }

                    if last_threat is None or current_threat != last_threat:
                        # print(json.dumps(current_threat, indent=4))
                        print("!!! New Threat Detected !!!" 
                          "\nSeqno=",last_seqno,
                          "\nSource_IP=",src_ip,
                          "\nDestiantion_IP=",dst_ip,
                          "\nSource_zone=",src_zone,
                          "\nProtocol=",protocol_type,
                          "\nthreat_type=",threat_type)
                        policy_rule_name = f"rule_Dos_{src_ip}_from_{src_zone}_{protocol_type}"
                        profile_name = f"Dos_block_{src_ip}_{protocol_type}"
                        create_dos_protection_profile(threat_type, protocol_type,profile_name)
                        create_dos_protection_policy(src_ip,src_zone,profile_name,policy_rule_name)

                        last_threat = current_threat

                    last_seqno = current_seqno
        time.sleep(interval)

# Start polling for logs every 1 second
poll_logs(api_key, interval=1)
