# Get_traffic_logs.py
import requests
import xml.etree.ElementTree as ET
import time
import os
from datetime import datetime

firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Track the latest receive_time processed
last_receive_time = None

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
            if status == 'success' and result is not None:
                job_status = result.find('job').find('status').text
                if job_status == 'FIN':
                    logs = result.find('.//logs').findall('entry')
                    log_list = []
                    for log in logs:
                        log_dict = {child.tag: child.text for child in log}
                        log_list.append(log_dict)
                    print(f"Job {job_id} finished. Retrieved {len(log_list)} logs.")
                    return log_list
                elif job_status in ('ACT', 'PEND'):
                    print("Job is still processing. Waiting...")
                    time.sleep(0.5)
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
    global last_receive_time

    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Fetch more logs initially to ensure we get enough recent ones
    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'nlogs': max_logs * 2  # Fetch 200 to filter down to 100 newest
    }

    print(f"Fetching logs at {datetime.now()}")
    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        try:
            response_xml = ET.fromstring(response.text)
            if response_xml.attrib['status'] == 'success':
                job_id = response_xml.find('.//job').text
                logs = get_job_result(api_key, job_id)

                if logs is None:
                    print("No logs retrieved from job.")
                    return None

                # Parse receive_time and sort logs by it (descending)
                for log in logs:
                    receive_time_str = log.get('receive_time')
                    try:
                        log['receive_time_dt'] = datetime.strptime(receive_time_str, "%Y/%m/%d %H:%M:%S")
                    except (ValueError, TypeError):
                        print(f"Invalid receive_time in log: {receive_time_str}")
                        log['receive_time_dt'] = datetime.min  # Fallback for sorting

                # Sort logs by receive_time (newest first)
                sorted_logs = sorted(logs, key=lambda x: x['receive_time_dt'], reverse=True)

                # Filter to only logs newer than last_receive_time (if set)
                if last_receive_time:
                    new_logs = [log for log in sorted_logs if log['receive_time_dt'] > last_receive_time]
                else:
                    new_logs = sorted_logs

                # Take the 100 most recent logs
                new_logs = new_logs[:max_logs]

                if new_logs:
                    last_receive_time = max(log['receive_time_dt'] for log in new_logs)
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