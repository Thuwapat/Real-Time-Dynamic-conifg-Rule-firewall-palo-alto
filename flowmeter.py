from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, ICMP
import time
import threading
import pandas as pd
import statistics

# Set network interface (modify as needed for your system)
NETWORK_INTERFACE = "Wi-Fi"  # Windows: "Wi-Fi", Linux/macOS: "eth0" or "wlan0"

# Dictionary to store flows (bidirectional flows)
flow_records = {}

def get_canonical_flow_key(packet):
    """
    Generate a bidirectional flow key using sorted endpoint tuples.
    For TCP/UDP packets, include ports if available; for others, use IP addresses.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = None
        dst_port = None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Use 0 if port is None so that the tuple can be sorted
        endpoint1 = (src_ip, src_port if src_port is not None else 0)
        endpoint2 = (dst_ip, dst_port if dst_port is not None else 0)
        if endpoint1 <= endpoint2:
            return (endpoint1, endpoint2, protocol)
        else:
            return (endpoint2, endpoint1, protocol)
    return None

def process_packet(packet):
    global flow_records
    timestamp = time.time()

    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto
    pkt_length = len(packet)
    raw_payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
    tcp_flags = packet[TCP].flags if packet.haslayer(TCP) else None

    # Use the canonical key so that both directions map to the same flow record.
    flow_key = get_canonical_flow_key(packet)
    if flow_key is None:
        return

    # If this is a new flow, initialize the record.
    if flow_key not in flow_records:
        # Define the forward direction as that of the very first packet.
        flow_records[flow_key] = {
            "fwd_src": src_ip,
            "fwd_dst": dst_ip,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "forward": {
                "packet_count": 0,
                "byte_count": 0,
                "packet_lengths": [],
                "iat": [],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "fin_count": 0,
                "syn_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "ack_count": 0,
                "urg_count": 0,
                "payload_max": raw_payload_len
            },
            "backward": {
                "packet_count": 0,
                "byte_count": 0,
                "packet_lengths": [],
                "iat": [],
                "first_seen": None,
                "last_seen": None,
                "fin_count": 0,
                "syn_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "ack_count": 0,
                "urg_count": 0,
                "payload_max": raw_payload_len
            }
        }

    flow = flow_records[flow_key]
    flow["last_seen"] = timestamp

    # Determine direction: if packet source equals the forward source then it's forward;
    # otherwise, if it equals the stored forward destination, consider it backward.
    if src_ip == flow["fwd_src"]:
        direction = "forward"
    elif src_ip == flow["fwd_dst"]:
        direction = "backward"
        if flow["backward"]["first_seen"] is None:
            flow["backward"]["first_seen"] = timestamp
            flow["backward"]["last_seen"] = timestamp
    else:
        direction = "forward"  # Fallback

    dir_record = flow[direction]

    # Calculate interarrival time (IAT) for this direction if not the first packet.
    if dir_record["packet_count"] > 0:
        iat = timestamp - dir_record["last_seen"]
        dir_record["iat"].append(iat)
    else:
        iat = 0

    # Update directional timestamps.
    if dir_record["packet_count"] == 0:
        dir_record["first_seen"] = timestamp
    dir_record["last_seen"] = timestamp

    # Update counters and lists.
    dir_record["packet_count"] += 1
    dir_record["byte_count"] += pkt_length
    dir_record["packet_lengths"].append(pkt_length)
    if raw_payload_len > dir_record["payload_max"]:
        dir_record["payload_max"] = raw_payload_len

    # Update TCP flag counts if applicable.
    if tcp_flags:
        flags = str(tcp_flags)
        if "F" in flags:
            dir_record["fin_count"] += 1
        if "S" in flags:
            dir_record["syn_count"] += 1
        if "R" in flags:
            dir_record["rst_count"] += 1
        if "P" in flags:
            dir_record["psh_count"] += 1
        if "A" in flags:
            dir_record["ack_count"] += 1
        if "U" in flags:
            dir_record["urg_count"] += 1

def compute_direction_stats(record):
    """
    Compute statistics (min, max, mean, std) for packet lengths and interarrival times.
    """
    stats = {}
    lengths = record["packet_lengths"]
    if lengths:
        stats["pkt_len_max"] = max(lengths)
        stats["pkt_len_min"] = min(lengths)
        stats["pkt_len_mean"] = statistics.mean(lengths)
        stats["pkt_len_std"] = statistics.stdev(lengths) if len(lengths) > 1 else 0
    else:
        stats["pkt_len_max"] = stats["pkt_len_min"] = stats["pkt_len_mean"] = stats["pkt_len_std"] = 0

    iats = record["iat"]
    if iats:
        stats["iat_max"] = max(iats)
        stats["iat_min"] = min(iats)
        stats["iat_mean"] = statistics.mean(iats)
        stats["iat_std"] = statistics.stdev(iats) if len(iats) > 1 else 0
    else:
        stats["iat_max"] = stats["iat_min"] = stats["iat_mean"] = stats["iat_std"] = 0
    return stats

def display_flows():
    while True:
        time.sleep(1)
        if flow_records:
            rows = []
            for key, flow in flow_records.items():
                overall_duration = flow["last_seen"] - flow["first_seen"]
                fwd_stats = compute_direction_stats(flow["forward"])
                bwd_stats = compute_direction_stats(flow["backward"])
                row = {
                    "fwd_src": flow["fwd_src"],
                    "fwd_dst": flow["fwd_dst"],
                    "fwd_pkt_count": flow["forward"]["packet_count"],
                    "bwd_pkt_count": flow["backward"]["packet_count"],
                    "fwd_byte_count": flow["forward"]["byte_count"],
                    "bwd_byte_count": flow["backward"]["byte_count"],
                    "flow_duration": overall_duration,
                    "fwd_pkt_len_max": fwd_stats["pkt_len_max"],
                    "fwd_pkt_len_min": fwd_stats["pkt_len_min"],
                    "fwd_pkt_len_mean": fwd_stats["pkt_len_mean"],
                    "fwd_pkt_len_std": fwd_stats["pkt_len_std"],
                    "fwd_iat_max": fwd_stats["iat_max"],
                    "fwd_iat_min": fwd_stats["iat_min"],
                    "fwd_iat_mean": fwd_stats["iat_mean"],
                    "fwd_iat_std": fwd_stats["iat_std"],
                    "bwd_pkt_len_max": bwd_stats["pkt_len_max"],
                    "bwd_pkt_len_min": bwd_stats["pkt_len_min"],
                    "bwd_pkt_len_mean": bwd_stats["pkt_len_mean"],
                    "bwd_pkt_len_std": bwd_stats["pkt_len_std"],
                    "bwd_iat_max": bwd_stats["iat_max"],
                    "bwd_iat_min": bwd_stats["iat_min"],
                    "bwd_iat_mean": bwd_stats["iat_mean"],
                    "bwd_iat_std": bwd_stats["iat_std"],
                    "fwd_fin_count": flow["forward"]["fin_count"],
                    "fwd_syn_count": flow["forward"]["syn_count"],
                    "fwd_rst_count": flow["forward"]["rst_count"],
                    "fwd_psh_count": flow["forward"]["psh_count"],
                    "fwd_ack_count": flow["forward"]["ack_count"],
                    "fwd_urg_count": flow["forward"]["urg_count"],
                    "bwd_fin_count": flow["backward"]["fin_count"],
                    "bwd_syn_count": flow["backward"]["syn_count"],
                    "bwd_rst_count": flow["backward"]["rst_count"],
                    "bwd_psh_count": flow["backward"]["psh_count"],
                    "bwd_ack_count": flow["backward"]["ack_count"],
                    "bwd_urg_count": flow["backward"]["urg_count"],
                }
                rows.append(row)
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
            for key, flow in flow_records.items():
                overall_duration = flow["last_seen"] - flow["first_seen"]
                fwd_stats = compute_direction_stats(flow["forward"])
                bwd_stats = compute_direction_stats(flow["backward"])
                row = {
                    "fwd_src": flow["fwd_src"],
                    "fwd_dst": flow["fwd_dst"],
                    "fwd_pkt_count": flow["forward"]["packet_count"],
                    "bwd_pkt_count": flow["backward"]["packet_count"],
                    "fwd_byte_count": flow["forward"]["byte_count"],
                    "bwd_byte_count": flow["backward"]["byte_count"],
                    "flow_duration": overall_duration,
                    "fwd_pkt_len_max": fwd_stats["pkt_len_max"],
                    "fwd_pkt_len_min": fwd_stats["pkt_len_min"],
                    "fwd_pkt_len_mean": fwd_stats["pkt_len_mean"],
                    "fwd_pkt_len_std": fwd_stats["pkt_len_std"],
                    "fwd_iat_max": fwd_stats["iat_max"],
                    "fwd_iat_min": fwd_stats["iat_min"],
                    "fwd_iat_mean": fwd_stats["iat_mean"],
                    "fwd_iat_std": fwd_stats["iat_std"],
                    "bwd_pkt_len_max": bwd_stats["pkt_len_max"],
                    "bwd_pkt_len_min": bwd_stats["pkt_len_min"],
                    "bwd_pkt_len_mean": bwd_stats["pkt_len_mean"],
                    "bwd_pkt_len_std": bwd_stats["pkt_len_std"],
                    "bwd_iat_max": bwd_stats["iat_max"],
                    "bwd_iat_min": bwd_stats["iat_min"],
                    "bwd_iat_mean": bwd_stats["iat_mean"],
                    "bwd_iat_std": bwd_stats["iat_std"],
                    "fwd_fin_count": flow["forward"]["fin_count"],
                    "fwd_syn_count": flow["forward"]["syn_count"],
                    "fwd_rst_count": flow["forward"]["rst_count"],
                    "fwd_psh_count": flow["forward"]["psh_count"],
                    "fwd_ack_count": flow["forward"]["ack_count"],
                    "fwd_urg_count": flow["forward"]["urg_count"],
                    "bwd_fin_count": flow["backward"]["fin_count"],
                    "bwd_syn_count": flow["backward"]["syn_count"],
                    "bwd_rst_count": flow["backward"]["rst_count"],
                    "bwd_psh_count": flow["backward"]["psh_count"],
                    "bwd_ack_count": flow["backward"]["ack_count"],
                    "bwd_urg_count": flow["backward"]["urg_count"],
                }
                rows.append(row)
            df = pd.DataFrame(rows)
            df.to_csv('active_flows.csv', index=False)
            print("Exported flows to active_flows.csv")

def start_sniffing():
    print(f"Starting packet capture on {NETWORK_INTERFACE}. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False, iface=NETWORK_INTERFACE)

# Start display and export threads.
display_thread = threading.Thread(target=display_flows, daemon=True)
export_thread = threading.Thread(target=export_to_csv, daemon=True)
display_thread.start()
export_thread.start()

try:
    start_sniffing()
except KeyboardInterrupt:
    print("\nCapture stopped. Exiting...")
