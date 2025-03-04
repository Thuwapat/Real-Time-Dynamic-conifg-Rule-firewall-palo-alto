import requests
import xml.etree.ElementTree as ET
import json
import time
import os

# Palo Alto firewall credentials and IP
firewall_ip = os.environ.get("FIREWALL_IP")
api_key = os.environ.get("API_KEY_PALO_ALTO")

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# เก็บค่าของ Session ID ล่าสุด
last_session_id = None

def get_job_result(api_key, job_id):
    """ดึงผลลัพธ์ของ Log จาก Palo Alto"""
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

def get_new_traffic_logs(api_key, log_type="traffic", max_logs=10):
    """ดึงเฉพาะ Traffic ที่มี Session ID ใหม่"""
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

                # กรองเฉพาะ Logs ที่มี Session ID ใหม่
                new_logs = []
                for log in logs:
                    session_id = log.get('sessionid', None)
                    if session_id and session_id != last_session_id:
                        new_logs.append(log)

                # อัปเดตค่า last_session_id
                if new_logs:
                    last_session_id = new_logs[-1]['sessionid']

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

def preprocess_traffic_log(log):
    """ แปลงข้อมูล Traffic Log ให้เป็น Feature Vector ที่โมเดลต้องการ """

    # แปลงค่าโปรโตคอลจากชื่อ (string) เป็นตัวเลข
    protocol_mapping = {"tcp": 6, "udp": 17, "icmp": 1}
    ip_protocol = protocol_mapping.get(log.get("proto", "").lower(), 0)  # ค่า default เป็น 0 ถ้าไม่พบ

    return {
        "Repeat Count": int(log.get("repeatcnt", 1)),
        "IP Protocol": ip_protocol,
        "Bytes": int(log.get("bytes", 0)),
        "Bytes Sent": int(log.get("bytes_sent", 0)),
        "Bytes Received": int(log.get("bytes_received", 0)),
        "Packets": int(log.get("packets", 0)),
        "Elapsed Time (sec)": float(log.get("elapsed", 1.0)),
        "Packets Sent": int(log.get("pkts_sent", 0)),
        "Packets Received": int(log.get("pkts_received", 0)),
        "Risk of app": int(log.get("risk_of_app", 1)),
        "Packets per second": int(log.get("packets", 0)) / (float(log.get("elapsed", 1.0)) + 1e-5),
        "Bytes per second": int(log.get("bytes", 0)) / (float(log.get("elapsed", 1.0)) + 1e-5),
        "Average packet size": int(log.get("bytes", 0)) / (int(log.get("packets", 1)) + 1e-5)
    }

# เรียกใช้ฟังก์ชันเพื่อดึงเฉพาะ Traffic ใหม่
if __name__ == "__main__":
    new_traffic_logs = get_new_traffic_logs(api_key)
    if new_traffic_logs:
        print(json.dumps(new_traffic_logs, indent=4))
