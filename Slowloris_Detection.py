# Slowloris_Detection.py
from collections import defaultdict
from datetime import datetime

def detect_slowloris_from_logs(logs, threshold_connections=10, time_window=1):
    """
    Detect Slowloris attack based on traffic logs, focusing on concurrent connections within a time window.
    - logs: List of traffic log dictionaries from Palo Alto Firewall.
    - threshold_connections: Minimum number of concurrent connections from a single IP to flag as suspicious (default: 10).
    - time_window: Time window in seconds to consider logs as concurrent (default: 1 second, matching POLL_INTERVAL).
    Returns a dictionary of source IPs suspected of Slowloris with their concurrent session counts.
    """
    source_ip_sessions = defaultdict(list)
    
    # Characteristics of Slowloris from your observations
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
    
    # Get the current time for reference (approximate time of log fetch)
    current_time = datetime.now()
    
    # Filter logs and group by source IP, ensuring they are within the time window
    for log in logs:
        source_ip = log.get('source-address')
        packets_sent = int(log.get('packets-sent', 0))
        packets_received = int(log.get('packets-received', 0))
        log_time_str = log.get('high-res-timestamp')  # High-resolution timestamp from logs
        
        # Parse the log timestamp
        try:
            log_time = datetime.strptime(log_time_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            time_diff = (current_time - log_time.replace(tzinfo=None)).total_seconds()
            if abs(time_diff) > time_window:  # Skip logs outside the 1-second window
                continue
        except (ValueError, TypeError):
            continue  # Skip if timestamp is missing or invalid
        
        # Check if log matches all Slowloris characteristics
        matches_characteristics = (
            log.get('application') == slowloris_characteristics['application'] and
            log.get('repeat-count') == slowloris_characteristics['repeat-count'] and
            log.get('session-end-reason') == slowloris_characteristics['session-end-reason'] and
            log.get('subcategory-of-app') == slowloris_characteristics['subcategory-of-app'] and
            log.get('category-of-app') == slowloris_characteristics['category-of-app'] and
            log.get('technology-of-app') == slowloris_characteristics['technology-of-app'] and
            log.get('risk-of-app') == slowloris_characteristics['risk-of-app'] and
            log.get('characteristic-of-app') == slowloris_characteristics['characteristic-of-app'] and
            log.get('tunneled-app') == slowloris_characteristics['tunneled-app'] and
            packets_sent <= 10 and  # Low packets sent
            packets_received <= 10  # Low packets received
        )
        
        if matches_characteristics:
            source_ip_sessions[source_ip].append(log)
    
    # Identify suspicious source IPs based on concurrent connections
    slowloris_candidates = {}
    for src_ip, sessions in source_ip_sessions.items():
        concurrent_count = len(sessions)  # Number of sessions within the 1-second window
        if concurrent_count >= threshold_connections:
            slowloris_candidates[src_ip] = concurrent_count
    
    return slowloris_candidates