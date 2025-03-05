# Get_onlynew_traffic.py
import requests
import xml.etree.ElementTree as ET
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Store the last seen Session ID globally
last_session_id = None

def get_job_result(api_key, job_id):
    """Retrieve the result of a log job from Palo Alto."""
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
            if status == 'success' and result is not None:
                job_status = result.find('job').find('status').text
                if job_status == 'FIN':
                    logs = result.find('.//logs').findall('entry')
                    log_list = []
                    for log in logs:
                        log_dict = {child.tag: child.text for child in log}
                        log_list.append(log_dict)
                    return log_list
                elif job_status in ('ACT', 'PEND'):
                    print("Job is still processing. Waiting...")
                    time.sleep(1)  # Shorter sleep for faster polling
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

def get_new_traffic_logs(api_key, log_type="traffic", max_logs=100):
    """Retrieve only traffic logs with new Session IDs."""
    global last_session_id

    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Payload for retrieving logs
    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'nlogs': max_logs
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        try:
            response_xml = ET.fromstring(response.text)
            if response_xml.attrib['status'] == 'success':
                job_id = response_xml.find('.//job').text
                logs = get_job_result(api_key, job_id)

                if logs is None:
                    return None

                # Filter logs to include only those with new Session IDs
                new_logs = []
                for log in logs:
                    session_id = log.get('sessionid')
                    if session_id and (last_session_id is None or int(session_id) > int(last_session_id)):
                        new_logs.append(log)

                # Update last_session_id to the highest seen
                if new_logs:
                    last_session_id = max([log['sessionid'] for log in new_logs if log.get('sessionid')], default=last_session_id)

                return new_logs
            else:
                print(f"Failed to retrieve logs: {response_xml.find('.//msg').text}")
        except ET.ParseError as e:
            print(f"Failed to parse response XML: {e}")
            print("Response content:")
            print(response.text)
    else:
        print(f"HTTP error: {response.status_code} - {response.text}")
    return None