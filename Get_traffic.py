import requests
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

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

def get_all_logs(api_key, log_type="traffic", max_logs=1):
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

def analyze_unique_ips_per_second(logs):
    """
    วิเคราะห์ Unique IP ใหม่ที่พบในแต่ละวินาทีจาก traffic logs
    """
    unique_ips = set()  # เก็บ IP ที่เคยพบแล้ว
    new_unique_ips_per_sec = defaultdict(set)  # เก็บ IP ใหม่ที่ไม่เคยเห็นมาก่อน แยกตามเวลา

    for log in logs:
        timestamp = log.get('receive_time')  # ต้องตรวจสอบว่า 'receive_time' คือฟิลด์ที่ถูกต้อง
        src_ip = log.get('src')  # ดึงค่า IP ต้นทาง
        if timestamp and src_ip:
            timestamp_sec = timestamp.split('.')[0]  # ตัดให้เหลือระดับวินาที
            if src_ip not in unique_ips:
                new_unique_ips_per_sec[timestamp_sec].add(src_ip)
                unique_ips.add(src_ip)

    # แสดงผลลัพธ์
    result = {time: len(ips) for time, ips in new_unique_ips_per_sec.items()}
    return result

# Retrieve all traffic logs
logs = get_all_logs(api_key)
if logs:
    unique_ip_analysis = analyze_unique_ips_per_second(logs)
    print("New Unique IP/S :")
    print(json.dumps(unique_ip_analysis, indent=4))
    for log in logs:
        print(f"Source IP: {log.get('src')}, Destination IP: {log.get('dst')}, Bytes Sent: {log.get('bytes')}")


