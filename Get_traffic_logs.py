# Get_traffic_logs.py
import requests
import xml.etree.ElementTree as ET
import time
import os
from datetime import datetime, timedelta

firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

last_fetch_time = None

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
    global last_fetch_time

    url = f"https://{firewall_ip}/api/"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    current_time = datetime.now()
    if last_fetch_time is None:
        last_fetch_time = current_time - timedelta(seconds=1)
    query_time = last_fetch_time.strftime("%Y/%m/%d %H:%M:%S")

    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'query': f"(receive_time geq '{query_time}')",
        'nlogs': max_logs
    }

    print(f"Fetching {max_logs} new logs since {query_time} at {current_time}")
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

                new_logs = []
                for log in logs:
                    log_time_str = log.get('high_res_timestamp')
                    try:
                        # Normalize timestamp: "2025-0306T01:03:04:18.545+07:00" -> "20250306T01:03:04.18545+07:00"
                        # Step 1: Remove hyphens between year, month, day
                        log_time_str = log_time_str.replace('-', '', 2)  # Remove first two hyphens
                        # Step 2: Replace the last colon (before microseconds) with a dot
                        parts = log_time_str.rsplit(':', 1)  # Split on the last colon
                        log_time_str = parts[0] + '.' + parts[1]  # Replace last : with .
                        log_time = datetime.strptime(log_time_str, "%Y%m%dT%H:%M:%S.%f%z")
                        if log_time > last_fetch_time:
                            new_logs.append(log)
                    except (ValueError, TypeError) as e:
                        print(f"Invalid timestamp in log: {log.get('high_res_timestamp')}, normalized to: {log_time_str}, error: {e}")
                        continue

                new_logs.sort(key=lambda x: datetime.strptime(x.get('high_res_timestamp', '1970-01-01T00:00:00.000+00:00').replace('-', '', 2).rsplit(':', 1)[0] + '.' + x.get('high_res_timestamp', '1970-01-01T00:00:00.000+00:00').rsplit(':', 1)[1], "%Y%m%dT%H:%M:%S.%f%z"), reverse=True)
                new_logs = new_logs[:max_logs]

                if new_logs:
                    latest_time_str = new_logs[0]['high_res_timestamp'].replace('-', '', 2).rsplit(':', 1)[0] + '.' + new_logs[0]['high_res_timestamp'].rsplit(':', 1)[1]
                    last_fetch_time = datetime.strptime(latest_time_str, "%Y%m%dT%H:%M:%S.%f%z")
                    print(f"Retrieved {len(new_logs)} new logs. Latest timestamp: {last_fetch_time}")
                    for log in new_logs[:5]:
                        print(f"Log: {log.get('src')} -> {log.get('dst')}, Time: {log.get('high_res_timestamp')}")
                else:
                    print("No new logs found since last fetch.")
                
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