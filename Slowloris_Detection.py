# Slowloris_Detection.py
from collections import defaultdict

def detect_slowloris_from_logs(logs, threshold_matches=5):
    """
    Detect Slowloris attack by analyzing a batch of traffic logs for characteristic matches.
    - logs: List of traffic log dictionaries from Palo Alto Firewall (e.g., 100 logs).
    - threshold_matches: Minimum number of logs from a single IP matching Slowloris characteristics to flag as suspicious (default: 5).
    Returns a dictionary of source IPs suspected of Slowloris with their match counts.
    """
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
    for src_ip, matched_logs in source_ip_matches.items():
        match_count = len(matched_logs)
        print(f"Source IP {src_ip} has {match_count} matching logs out of {len(logs)}")
        if match_count >= threshold_matches:
            slowloris_candidates[src_ip] = match_count
    
    return slowloris_candidates