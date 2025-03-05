from datetime import datetime
from collections import defaultdict

def detect_slowloris(actsession_data, threshold_duration=300, threshold_connections=10, threshold_byte_count=5000):
    """
    Detect Slowloris attack based on active session data.
    - threshold_duration: Minimum session duration in seconds to consider it suspicious (default: 300s = 5min).
    - threshold_connections: Minimum number of connections from a single IP to flag as suspicious (default: 10).
    - threshold_byte_count: Maximum byte count for a session to be considered low-traffic (default: 5000 bytes).
    """
    current_time = datetime.now()
    source_ip_sessions = defaultdict(list)
    
    # Parse active sessions
    sessions = actsession_data.findall(".//entry")
    for session in sessions:
        source_ip = session.find('source').text
        dport = int(session.find('dport').text)
        start_time_str = session.find('start-time').text
        byte_count = int(session.find('total-byte-count').text)
        proto = int(session.find('proto').text)  # 6 = TCP
        
        # Only consider TCP sessions targeting HTTP/HTTPS ports
        if proto != 6 or dport not in [80, 443]:
            continue
        
        # Parse start time and calculate duration
        try:
            start_time = datetime.strptime(start_time_str, "%a %b %d %H:%M:%S %Y")
            duration = (current_time - start_time).total_seconds()
        except ValueError:
            continue
        
        # Collect session info
        session_info = {
            'duration': duration,
            'byte_count': byte_count,
            'dport': dport
        }
        source_ip_sessions[source_ip].append(session_info)
    
    # Analyze for Slowloris characteristics
    slowloris_candidates = {}
    for src_ip, sessions in source_ip_sessions.items():
        if len(sessions) >= threshold_connections:
            long_lived_low_traffic = [
                s for s in sessions 
                if s['duration'] >= threshold_duration and s['byte_count'] <= threshold_byte_count
            ]
            if len(long_lived_low_traffic) >= threshold_connections:
                slowloris_candidates[src_ip] = len(long_lived_low_traffic)
    
    return slowloris_candidates