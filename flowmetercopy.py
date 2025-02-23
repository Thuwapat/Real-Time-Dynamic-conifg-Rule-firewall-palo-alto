from scapy.all import sniff, IP, TCP, UDP, Ether
import time
import threading
import pandas as pd
import statistics

# Set network interface (Modify based on your system)
NETWORK_INTERFACE = "Wi-Fi"  # Windows: "Wi-Fi", Linux/macOS: "eth0" or "wlan0"

# Dictionary to store active flows
flow_records = {}

# Function to generate a unique key for each flow
def get_flow_key(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    return None

# Packet processing function
def process_packet(packet):
    global flow_records
    if IP in packet:
        flow_key = get_flow_key(packet)
        timestamp = time.time()

        if flow_key:
            if flow_key not in flow_records:
                # Initialize new flow
                flow_records[flow_key] = {
                    "src_ip": flow_key[0], "dst_ip": flow_key[1],
                    "src_port": flow_key[2], "dst_port": flow_key[3],
                    "protocol": flow_key[4],
                    "first_seen": timestamp, "last_seen": timestamp,
                    "packet_count": 1, "byte_count": len(packet),
                    "pkt_len_max": len(packet), "pkt_len_min": len(packet),
                    "pkt_len_sum": len(packet), "pkt_len_var": [],
                    "flow_iat": [], "flow_iat_mean": 0,
                    "flow_iat_max": 0, "flow_iat_min": float("inf"), "flow_iat_std": 0,
                    "tcp_flags": [], "fwd_win_bytes": None, "bwd_win_bytes": None,
                    "seq_number": None, "ack_number": None,
                    "udp_payload_size": None, "active_times": [], "idle_times": [],
                    "src_mac": packet[Ether].src if Ether in packet else None,
                    "dst_mac": packet[Ether].dst if Ether in packet else None,
                    "fin_flag_count": 0, "syn_flag_count": 0, "rst_flag_count": 0,
                    "psh_flag_count": 0, "ack_flag_count": 0, "urg_flag_count": 0,
                    "flow_duration": 0, "packets_per_second": 0, "bytes_per_second": 0
                }
            else:
                # Update existing flow
                flow = flow_records[flow_key]
                flow["last_seen"] = timestamp
                flow["packet_count"] += 1
                flow["byte_count"] += len(packet)
                flow["pkt_len_max"] = max(flow["pkt_len_max"], len(packet))
                flow["pkt_len_min"] = min(flow["pkt_len_min"], len(packet))
                flow["pkt_len_var"].append(len(packet))

                # Calculate Inter-Arrival Time (IAT)
                iat = timestamp - flow["last_seen"]
                flow["flow_iat"].append(iat)
                if iat > 0:
                    flow["flow_iat_max"] = max(flow["flow_iat_max"], iat)
                    flow["flow_iat_min"] = min(flow["flow_iat_min"], iat)
                    flow["flow_iat_mean"] = statistics.mean(flow["flow_iat"])
                    flow["flow_iat_std"] = statistics.stdev(flow["flow_iat"]) if len(flow["flow_iat"]) > 1 else 0

                # TCP/UDP Features
                if TCP in packet:
                    flow["seq_number"] = packet[TCP].seq
                    flow["ack_number"] = packet[TCP].ack
                    flow["fwd_win_bytes"] = packet[TCP].window
                    tcp_flags = packet[TCP].flags
                    flow["tcp_flags"].append(tcp_flags)

                    if "F" in tcp_flags: flow["fin_flag_count"] += 1
                    if "S" in tcp_flags: flow["syn_flag_count"] += 1
                    if "R" in tcp_flags: flow["rst_flag_count"] += 1
                    if "P" in tcp_flags: flow["psh_flag_count"] += 1
                    if "A" in tcp_flags: flow["ack_flag_count"] += 1
                    if "U" in tcp_flags: flow["urg_flag_count"] += 1

                if UDP in packet:
                    flow["udp_payload_size"] = len(packet[UDP].payload)

                # Update Flow Statistics
                flow["flow_duration"] = flow["last_seen"] - flow["first_seen"]
                flow["packets_per_second"] = flow["packet_count"] / flow["flow_duration"] if flow["flow_duration"] > 0 else 0
                flow["bytes_per_second"] = flow["byte_count"] / flow["flow_duration"] if flow["flow_duration"] > 0 else 0

# Function to display captured flows every second
def display_flows():
    while True:
        time.sleep(1)
        if flow_records:
            df = pd.DataFrame.from_dict(flow_records, orient='index')
            print("\n--- Active Flows ---")
            print(df[[
                "src_ip", "dst_ip", "src_port", "dst_port", "protocol", 
                "packet_count", "byte_count", "pkt_len_max", "pkt_len_min", 
                "flow_iat_max", "flow_iat_min", "flow_iat_mean", "flow_iat_std", 
                "flow_duration", "packets_per_second", "bytes_per_second",
                "fwd_win_bytes", "seq_number", "ack_number",
                "fin_flag_count", "syn_flag_count", "rst_flag_count",
                "psh_flag_count", "ack_flag_count", "urg_flag_count"
            ]])
            print("\n--------------------\n")
        else:
            print("\nNo active flows detected...\n")

# Start sniffing in a separate thread
def start_sniffing():
    print(f"Starting packet capture on {NETWORK_INTERFACE}. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False, iface=NETWORK_INTERFACE)

# Run the display function in a separate thread
display_thread = threading.Thread(target=display_flows, daemon=True)
display_thread.start()

# Start packet sniffing (blocking operation)
try:
    start_sniffing()
except KeyboardInterrupt:
    print("\nCapture stopped. Exiting...")
