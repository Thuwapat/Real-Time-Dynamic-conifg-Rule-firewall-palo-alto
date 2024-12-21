import requests
import xml.etree.ElementTree as ET
import json
import time

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.11.100"
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="  # You can generate an API key from the Palo Alto GUI

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

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

def get_all_logs(api_key, log_type="threat", max_logs=1):
    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Empty query to fetch all logs
    query = ""

    # Payload for retrieving logs
    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'query': query,
        'nlogs': max_logs
    }

    # Send the API request
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


if __name__ == "__main__":
    logs = get_all_logs(api_key)
    if logs:
        print(json.dumps(logs, indent=4))
