from collections import defaultdict
from datetime import datetime, timedelta

def detect_slowloris_from_logs(logs, threshold_matches=5, time_window=1):
    source_ip_matches = defaultdict(list)
    
    slowloris_characteristics = {
        'application': 'web-browsing',
        'repeat-count': '1',
        'session-end-reason': ['tcp-rst-from-server', 'aged-out', 'tcp-fin'],  # เปลี่ยนเป็นลิสต์
        'subcategory-of-app': 'internet-utility',
        'category-of-app': 'general-internet',
        'technology-of-app': 'browser-based',
        'risk-of-app': '4',
        'characteristic-of-app': 'used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use',
        'tunneled-app': 'web-browsing'
    }
    
    print(f"Total logs received for analysis: {len(logs)}")
    
    for log in logs:
        source_ip = log.get('src')
        packets_sent = int(log.get('pkts_sent', 0))
        packets_received = int(log.get('pkts_received', 0))
        bytes_sent = int(log.get('bytes_sent', 0))
        bytes_received = int(log.get('bytes_received', 0))
        receive_time_dt = log.get('receive_time_dt')  
        
        # check receive_time_dt
        if receive_time_dt is None:
            print(f"Skipping log from {source_ip} due to missing or invalid receive_time")
            continue
        
        matches_characteristics = (
            log.get('app') == slowloris_characteristics['application'] and
            log.get('repeatcnt') == slowloris_characteristics['repeat-count'] and
            log.get('session_end_reason') in slowloris_characteristics['session-end-reason'] and  
            log.get('subcategory_of_app') == slowloris_characteristics['subcategory-of-app'] and
            log.get('category_of_app') == slowloris_characteristics['category-of-app'] and
            log.get('technology_of_app') == slowloris_characteristics['technology-of-app'] and
            log.get('risk_of_app') == slowloris_characteristics['risk-of-app'] and
            log.get('characteristic_of_app') == slowloris_characteristics['characteristic-of-app'] and
            log.get('tunneled_app') == slowloris_characteristics['tunneled-app'] and
            packets_sent <= 15 and
            packets_received <= 15 and
            bytes_sent <= 5000 and
            bytes_received <=5000
        )
        
        if matches_characteristics:
            source_ip_matches[source_ip].append(receive_time_dt)
            print(f"Matched log from {source_ip}: {receive_time_dt}, packets: {packets_sent}/{packets_received}")
    
    slowloris_candidates = {}
    for src_ip, timestamps in source_ip_matches.items():
        match_count = len(timestamps)
        print(f"Source IP {src_ip} has {match_count} matching logs")
        
        if match_count < threshold_matches:
            continue
        
        # sort timestamp
        timestamps.sort()
        
        # Check Frequency in time window 1 sec
        for i in range(len(timestamps) - threshold_matches + 1):
            window = timestamps[i:i + threshold_matches]
            time_diff = window[-1] - window[0]
            if time_diff <= timedelta(seconds=time_window):
                slowloris_candidates[src_ip] = match_count
                print(f"Slowloris detected from {src_ip}: {match_count} logs in {time_diff.total_seconds():.2f} sec")
                break
    
    return slowloris_candidates