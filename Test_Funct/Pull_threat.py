############# This pull threat traffic every 1s ###############
import requests
import xml.etree.ElementTree as ET
import json
import time

# Palo Alto firewall credentials and IP
firewall_ip = "192.168.11.100"
api_key = "LUFRPT1FM2lUb0U5ZFRacHdSZU9hS1pQOGp2VzVmRkk9MXhaQWdwVmlpVEFOUWV5Q3F1UzR2NkhUbW02YXFhT1Avb2xIYmJ5dGhnbCtNL1Z3L0hjdDJTTlhpRlJ5M0hMNg=="  # Replace with your actual API key

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

    # Query to fetch logs with seqno greater than the last seen log's seqno
    query = ""
    if last_seqno:
        query = f"(seqno geq {last_seqno})"  # Only fetch logs with seqno greater than the last one

    # Payload for retrieving logs
    payload = {
        'type': 'log',
        'log-type': log_type,
        'key': api_key,
        'query': query,
        'nlogs': max_logs  # Fetch multiple logs in case multiple new ones come in
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

def poll_logs(api_key, interval=1):
    last_seqno = None  # Track the latest log's seqno
    while True:
        # Fetch new logs that have a seqno greater than the last seen log
        logs = get_new_logs(api_key, last_seqno=last_seqno)
        if logs:
            # Process and print the logs
            for log in logs:
                current_seqno = int(log['seqno'])
                if last_seqno is None or current_seqno > last_seqno:
                    ###### GET Specific data ##########
                    src_ip = log.get('src')
                    dst_ip = log.get('dst')
                    #print(json.dumps(log, indent=4))
                    print("!!! New Threat Detected !!!" 
                          "\nSeqno=",last_seqno,
                          "\nSource_IP=",src_ip,
                          "\nDestiantion_IP=",dst_ip)
                    # Update last_seqno to the newest log's seqno after processing
                    last_seqno = current_seqno
        # Sleep before polling again
        time.sleep(interval)


################### MAIN FUNCUTION #########################
# Start polling for logs every 1 second
poll_logs(api_key, interval=1)
