from collections import defaultdict
from datetime import datetime, timedelta

def detect_slowloris_from_logs(logs, threshold_matches=5, time_window=1):
    source_ip_matches = defaultdict(list)
    
    slowloris_characteristics = {
        'application': 'web-browsing',
        'repeat-count': '1',
        'session-end-reason': 'tcp-rst-from-server',
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
        log_time_str = log.get('receive_time')  # Use receive_time for debug
        
        matches_characteristics = (
            log.get('app') == slowloris_characteristics['application'] and
            log.get('repeatcnt') == slowloris_characteristics['repeat-count'] and
            log.get('session_end_reason') == slowloris_characteristics['session-end-reason'] and
            log.get('subcategory_of_app') == slowloris_characteristics['subcategory-of-app'] and
            log.get('category_of_app') == slowloris_characteristics['category-of-app'] and
            log.get('technology_of_app') == slowloris_characteristics['technology-of-app'] and
            log.get('risk_of_app') == slowloris_characteristics['risk-of-app'] and
            log.get('characteristic_of_app') == slowloris_characteristics['characteristic-of-app'] and
            log.get('tunneled_app') == slowloris_characteristics['tunneled-app'] and
            packets_sent <= 15 and
            packets_received <= 15
        )
        
        if matches_characteristics:
            source_ip_matches[source_ip].append(log)
            print(f"Matched log from {source_ip}: {log_time_str}, packets: {packets_sent}/{packets_received}")
    
    slowloris_candidates = {}
    for src_ip, timestamps in source_ip_matches.items():
        if len(timestamps) < threshold_matches:
            continue
        timestamps.sort()
        for i in range(len(timestamps) - threshold_matches + 1):
            window = timestamps[i:i + threshold_matches]
            if window[-1] - window[0] <= timedelta(seconds=time_window):
                slowloris_candidates[src_ip] = len(timestamps)
                print(f"Slowloris detected from {src_ip}: {len(timestamps)} logs in {time_window} sec")
                break
    
    return slowloris_candidates