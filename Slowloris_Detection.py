# Slowloris_Detection.py
from collections import defaultdict
from datetime import datetime

def detect_slowloris_from_logs(logs, fetch_time, threshold_connections=5, time_window=2):
    """
    Detect Slowloris attack based on traffic logs, focusing on concurrent connections within a time window.
    - logs: List of traffic log dictionaries from Palo Alto Firewall.
    - fetch_time: Time when logs were fetched, for accurate time window comparison.
    - threshold_connections: Minimum number of concurrent connections from a single IP to flag as suspicious (default: 5).
    - time_window: Time window in seconds to consider logs as concurrent (default: 2 seconds).
    Returns a dictionary of source IPs suspected of Slowloris with their concurrent session counts.
    """
    source_ip_sessions = defaultdict(list)
    
    # Characteristics based on your latest log
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
    
    print(f"Fetch time for detection: {fetch_time}")
    print(f"Total logs received: {len(logs)}")
    
    # Filter logs and group by source IP
    for log in logs:
        source_ip = log.get('src')
        packets_sent = int(log.get('pkts_sent', 0))
        packets_received = int(log.get('pkts_received', 0))
        log_time_str = log.get('high_res_timestamp')
        
        # Parse the log timestamp
        try:
            log_time = datetime.strptime(log_time_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            time_diff = (fetch_time - log_time.replace(tzinfo=None)).total_seconds()
            if abs(time_diff) > time_window:
                print(f"Log skipped - outside time window: {log_time_str}, diff: {time_diff:.3f}s")
                continue
        except (ValueError, TypeError):
            print(f"Invalid timestamp in log: {log_time_str}")
            continue
        
        # Check if log matches all Slowloris characteristics
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
            packets_sent <= 50 and
            packets_received <= 50
        )
        
        if matches_characteristics:
            source_ip_sessions[source_ip].append(log)
            print(f"Matched log from {source_ip}: {log_time_str}, packets: {packets_sent}/{packets_received}")
    
    # Identify suspicious source IPs
    slowloris_candidates = {}
    for src_ip, sessions in source_ip_sessions.items():
        concurrent_count = len(sessions)
        print(f"Source IP {src_ip} has {concurrent_count} matching sessions")
        if concurrent_count >= threshold_connections:
            slowloris_candidates[src_ip] = concurrent_count
    
    return slowloris_candidates