from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, ICMP
import time
import threading
import pandas as pd
import statistics

# Set network interface (modify as needed for your system)
NETWORK_INTERFACE = "Wi-Fi"  # For Linux/macOS, use "eth0" or "wlan0" as appropriate

# Global dictionary to store flows; key is the canonical (bidirectional) flow key.
flow_records = {}

def get_canonical_flow_key(packet):
    """
    Generate a bidirectional flow key using sorted endpoints.
    For TCP/UDP packets, include ports if available; for other protocols, default to 0.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)
        if endpoint1 <= endpoint2:
            return (endpoint1, endpoint2, protocol)
        else:
            return (endpoint2, endpoint1, protocol)
    return None

def init_flow_record(packet, timestamp):
    """
    Initialize a new flow record. The first packet defines the forward direction.
    Additional raw data (e.g., lists of packet lengths and interarrival times)
    are stored for computing derived features later.
    """
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)
    raw_payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
    tcp_flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ""
    
    record = {
        # Basic flow timing and totals:
        'first_seen': timestamp,
        'last_seen': timestamp,
        'flow_duration': 0,
        'total_packets': 1,
        'total_bytes': pkt_len,
        # Forward direction is defined by the first packet:
        'fwd_src': src_ip,
        'fwd_dst': dst_ip,
        # Forward features:
        'fwd_pkt_count': 1,
        'fwd_byte_count': pkt_len,
        'fwd_pkt_lengths': [pkt_len],
        'fwd_iat': [],  # Interarrival times for forward packets
        'fwd_fin_count': 1 if "F" in tcp_flags else 0,
        'fwd_syn_count': 1 if "S" in tcp_flags else 0,
        'fwd_rst_count': 1 if "R" in tcp_flags else 0,
        'fwd_psh_count': 1 if "P" in tcp_flags else 0,
        'fwd_ack_count': 1 if "A" in tcp_flags else 0,
        'fwd_urg_count': 1 if "U" in tcp_flags else 0,
        'fwd_payload_max': raw_payload_len,
        'fwd_last_seen': timestamp,  # Used to compute IATs
        # Backward features (will be updated when packets from the other direction arrive):
        'bwd_pkt_count': 0,
        'bwd_byte_count': 0,
        'bwd_pkt_lengths': [],
        'bwd_iat': [],
        'bwd_fin_count': 0,
        'bwd_syn_count': 0,
        'bwd_rst_count': 0,
        'bwd_psh_count': 0,
        'bwd_ack_count': 0,
        'bwd_urg_count': 0,
        'bwd_payload_max': 0,
        'bwd_last_seen': None,
    }
    return record

def update_flow_record(record, packet, timestamp):
    """
    Update the flow record with data from a new packet.
    Determine if the packet is in the forward or backward direction and update accordingly.
    """
    record['last_seen'] = timestamp
    record['total_packets'] += 1
    record['total_bytes'] += len(packet)
    
    src_ip = packet[IP].src
    # Determine direction: if source matches the forward source, it's forward; otherwise, backward.
    direction = 'fwd' if src_ip == record['fwd_src'] else 'bwd'
    pkt_len = len(packet)
    raw_payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
    tcp_flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ""
    
    if direction == 'fwd':
        # Compute interarrival time for forward packets.
        if record['fwd_pkt_count'] > 0:
            iat = timestamp - record['fwd_last_seen']
            record['fwd_iat'].append(iat)
        record['fwd_last_seen'] = timestamp
        
        record['fwd_pkt_count'] += 1
        record['fwd_byte_count'] += pkt_len
        record['fwd_pkt_lengths'].append(pkt_len)
        if raw_payload_len > record['fwd_payload_max']:
            record['fwd_payload_max'] = raw_payload_len
            
        if "F" in tcp_flags: record['fwd_fin_count'] += 1
        if "S" in tcp_flags: record['fwd_syn_count'] += 1
        if "R" in tcp_flags: record['fwd_rst_count'] += 1
        if "P" in tcp_flags: record['fwd_psh_count'] += 1
        if "A" in tcp_flags: record['fwd_ack_count'] += 1
        if "U" in tcp_flags: record['fwd_urg_count'] += 1
    else:
        # Backward direction processing.
        if record['bwd_pkt_count'] > 0:
            iat = timestamp - record.get('bwd_last_seen', record['first_seen'])
            record['bwd_iat'].append(iat)
        record['bwd_last_seen'] = timestamp
        
        record['bwd_pkt_count'] += 1
        record['bwd_byte_count'] += pkt_len
        record['bwd_pkt_lengths'].append(pkt_len)
        if raw_payload_len > record['bwd_payload_max']:
            record['bwd_payload_max'] = raw_payload_len
            
        if "F" in tcp_flags: record['bwd_fin_count'] += 1
        if "S" in tcp_flags: record['bwd_syn_count'] += 1
        if "R" in tcp_flags: record['bwd_rst_count'] += 1
        if "P" in tcp_flags: record['bwd_psh_count'] += 1
        if "A" in tcp_flags: record['bwd_ack_count'] += 1
        if "U" in tcp_flags: record['bwd_urg_count'] += 1

def compute_additional_features(record):
    """
    Compute derived statistics and ratios for both forward and backward directions.
    Extend this function to calculate all additional features from CICFlowMeterV3.
    """
    # Flow duration.
    record['flow_duration'] = record['last_seen'] - record['first_seen']
    
    # Forward packet length statistics.
    if record['fwd_pkt_lengths']:
        record['fwd_pkt_len_max'] = max(record['fwd_pkt_lengths'])
        record['fwd_pkt_len_min'] = min(record['fwd_pkt_lengths'])
        record['fwd_pkt_len_mean'] = statistics.mean(record['fwd_pkt_lengths'])
        record['fwd_pkt_len_std'] = statistics.stdev(record['fwd_pkt_lengths']) if len(record['fwd_pkt_lengths']) > 1 else 0
    else:
        record['fwd_pkt_len_max'] = record['fwd_pkt_len_min'] = record['fwd_pkt_len_mean'] = record['fwd_pkt_len_std'] = 0
    
    # Forward interarrival time statistics.
    if record['fwd_iat']:
        record['fwd_iat_max'] = max(record['fwd_iat'])
        record['fwd_iat_min'] = min(record['fwd_iat'])
        record['fwd_iat_mean'] = statistics.mean(record['fwd_iat'])
        record['fwd_iat_std'] = statistics.stdev(record['fwd_iat']) if len(record['fwd_iat']) > 1 else 0
    else:
        record['fwd_iat_max'] = record['fwd_iat_min'] = record['fwd_iat_mean'] = record['fwd_iat_std'] = 0
    
    # Backward packet length statistics.
    if record['bwd_pkt_lengths']:
        record['bwd_pkt_len_max'] = max(record['bwd_pkt_lengths'])
        record['bwd_pkt_len_min'] = min(record['bwd_pkt_lengths'])
        record['bwd_pkt_len_mean'] = statistics.mean(record['bwd_pkt_lengths'])
        record['bwd_pkt_len_std'] = statistics.stdev(record['bwd_pkt_lengths']) if len(record['bwd_pkt_lengths']) > 1 else 0
    else:
        record['bwd_pkt_len_max'] = record['bwd_pkt_len_min'] = record['bwd_pkt_len_mean'] = record['bwd_pkt_len_std'] = 0
    
    # Backward interarrival time statistics.
    if record['bwd_iat']:
        record['bwd_iat_max'] = max(record['bwd_iat'])
        record['bwd_iat_min'] = min(record['bwd_iat'])
        record['bwd_iat_mean'] = statistics.mean(record['bwd_iat'])
        record['bwd_iat_std'] = statistics.stdev(record['bwd_iat']) if len(record['bwd_iat']) > 1 else 0
    else:
        record['bwd_iat_max'] = record['bwd_iat_min'] = record['bwd_iat_mean'] = record['bwd_iat_std'] = 0

    # Example derived ratios:
    record['fwd_bwd_pkt_ratio'] = (record['fwd_pkt_count'] / record['bwd_pkt_count']
                                   if record['bwd_pkt_count'] > 0 else None)
    record['fwd_bwd_byte_ratio'] = (record['fwd_byte_count'] / record['bwd_byte_count']
                                    if record['bwd_byte_count'] > 0 else None)
    
    # [Add additional features here to fully replicate CICFlowMeterV3]
    # For example: advanced statistical measures, entropy of packet sizes, etc.

def process_packet(packet):
    timestamp = time.time()
    if not packet.haslayer(IP):
        return
    flow_key = get_canonical_flow_key(packet)
    if flow_key is None:
        return
    if flow_key not in flow_records:
        flow_records[flow_key] = init_flow_record(packet, timestamp)
    else:
        update_flow_record(flow_records[flow_key], packet, timestamp)

def display_flows():
    while True:
        time.sleep(1)
        if flow_records:
            rows = []
            for key, record in flow_records.items():
                compute_additional_features(record)
                rows.append(record)
            df = pd.DataFrame(rows)
            print("\n--- Active Flows ---")
            print(df)
            print("\n--------------------\n")
        else:
            print("\nNo active flows detected...\n")

def export_to_csv():
    while True:
        time.sleep(10)  # Adjust export interval as needed.
        if flow_records:
            rows = []
            for key, record in flow_records.items():
                compute_additional_features(record)
                rows.append(record)
            df = pd.DataFrame(rows)
            df.to_csv('active_flows.csv', index=False)
            print("Exported flows to active_flows.csv")

def start_sniffing():
    print(f"Starting packet capture on {NETWORK_INTERFACE}. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False, iface=NETWORK_INTERFACE)

# Start background threads for display and CSV export.
display_thread = threading.Thread(target=display_flows, daemon=True)
export_thread = threading.Thread(target=export_to_csv, daemon=True)
display_thread.start()
export_thread.start()

try:
    start_sniffing()
except KeyboardInterrupt:
    print("\nCapture stopped. Exiting...")
