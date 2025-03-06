from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, ICMP
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
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = None
            dst_port = None
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    return None

# Packet processing function with extended data capture
def process_packet(packet):
    global flow_records
    timestamp = time.time()

    # Extract Ethernet layer fields
    eth_src = packet[Ether].src if packet.haslayer(Ether) else None
    eth_dst = packet[Ether].dst if packet.haslayer(Ether) else None
    eth_type = packet[Ether].type if packet.haslayer(Ether) else None

    # Extract IP layer fields (skip if no IP)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        ip_version = ip_layer.version
        ip_ihl = ip_layer.ihl
        ip_tos = ip_layer.tos
        ip_len = ip_layer.len
        ip_id = ip_layer.id
        ip_flags = ip_layer.flags
        ip_frag = ip_layer.frag
        ip_ttl = ip_layer.ttl
        ip_proto = ip_layer.proto
        ip_chksum = ip_layer.chksum
    else:
        return

    # Extract TCP fields if present
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        tcp_sport = tcp_layer.sport
        tcp_dport = tcp_layer.dport
        tcp_seq = tcp_layer.seq
        tcp_ack = tcp_layer.ack
        tcp_dataofs = getattr(tcp_layer, 'dataofs', None)
        tcp_reserved = getattr(tcp_layer, 'reserved', None)
        tcp_flags = tcp_layer.flags
        tcp_window = tcp_layer.window
        tcp_chksum = tcp_layer.chksum
        tcp_urgptr = tcp_layer.urgptr
        tcp_options = getattr(tcp_layer, 'options', None)
    else:
        tcp_sport = tcp_dport = tcp_seq = tcp_ack = tcp_dataofs = tcp_reserved = tcp_flags = tcp_window = tcp_chksum = tcp_urgptr = tcp_options = None

    # Extract UDP fields if present
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        udp_sport = udp_layer.sport
        udp_dport = udp_layer.dport
        udp_len = getattr(udp_layer, 'len', None)
        udp_chksum = udp_layer.chksum
    else:
        udp_sport = udp_dport = udp_len = udp_chksum = None

    # Extract ICMP fields if present
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        icmp_id = getattr(icmp_layer, 'id', None)
        icmp_seq = getattr(icmp_layer, 'seq', None)
    else:
        icmp_type = icmp_code = icmp_id = icmp_seq = None

    # Extract Raw payload data if present
    if packet.haslayer(Raw):
        raw_payload_len = len(packet[Raw].load)
    else:
        raw_payload_len = 0

    # Determine flow key for aggregation
    flow_key = get_flow_key(packet)
    if not flow_key:
        return

    # If flow does not exist, initialize a new record with all captured fields
    if flow_key not in flow_records:
        flow_records[flow_key] = {
            # Ethernet fields
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "eth_type": eth_type,
            # IP fields
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "ip_version": ip_version,
            "ip_ihl": ip_ihl,
            "ip_tos": ip_tos,
            "ip_len": ip_len,
            "ip_id": ip_id,
            "ip_flags": ip_flags,
            "ip_frag": ip_frag,
            "ip_ttl": ip_ttl,
            "ip_proto": ip_proto,
            "ip_chksum": ip_chksum,
            # TCP fields
            "tcp_sport": tcp_sport,
            "tcp_dport": tcp_dport,
            "tcp_seq": tcp_seq,
            "tcp_ack": tcp_ack,
            "tcp_dataofs": tcp_dataofs,
            "tcp_reserved": tcp_reserved,
            "tcp_flags": [tcp_flags] if tcp_flags is not None else [],
            "tcp_window": tcp_window,
            "tcp_chksum": tcp_chksum,
            "tcp_urgptr": tcp_urgptr,
            "tcp_options": tcp_options,
            # UDP fields
            "udp_sport": udp_sport,
            "udp_dport": udp_dport,
            "udp_len": udp_len,
            "udp_chksum": udp_chksum,
            # ICMP fields
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_id": icmp_id,
            "icmp_seq": icmp_seq,
            # Aggregated flow stats
            "first_seen": timestamp,
            "last_seen": timestamp,
            "packet_count": 1,
            "byte_count": len(packet),
            "pkt_len_max": len(packet),
            "pkt_len_min": len(packet),
            "pkt_len_var": [len(packet)],
            "flow_iat": [],
            "flow_iat_mean": 0,
            "flow_iat_max": 0,
            "flow_iat_min": float("inf"),
            "flow_iat_std": 0,
            "fin_flag_count": 1 if (tcp_flags and "F" in tcp_flags) else 0,
            "syn_flag_count": 1 if (tcp_flags and "S" in tcp_flags) else 0,
            "rst_flag_count": 1 if (tcp_flags and "R" in tcp_flags) else 0,
            "psh_flag_count": 1 if (tcp_flags and "P" in tcp_flags) else 0,
            "ack_flag_count": 1 if (tcp_flags and "A" in tcp_flags) else 0,
            "urg_flag_count": 1 if (tcp_flags and "U" in tcp_flags) else 0,
            "flow_duration": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            # Maximum raw payload seen in this flow
            "payload_max": raw_payload_len
        }
    else:
        # Update existing flow record
        flow = flow_records[flow_key]
        old_last_seen = flow["last_seen"]
        iat = timestamp - old_last_seen  # Calculate interarrival time before updating
        flow["last_seen"] = timestamp
        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)
        flow["pkt_len_max"] = max(flow["pkt_len_max"], len(packet))
        flow["pkt_len_min"] = min(flow["pkt_len_min"], len(packet))
        flow["pkt_len_var"].append(len(packet))
        flow["flow_iat"].append(iat)
        if iat > 0:
            flow["flow_iat_max"] = max(flow["flow_iat_max"], iat)
            flow["flow_iat_min"] = min(flow["flow_iat_min"], iat)
            flow["flow_iat_mean"] = statistics.mean(flow["flow_iat"])
            flow["flow_iat_std"] = statistics.stdev(flow["flow_iat"]) if len(flow["flow_iat"]) > 1 else 0

        # Update Ethernet info
        flow["eth_src"] = eth_src
        flow["eth_dst"] = eth_dst
        flow["eth_type"] = eth_type

        # Update IP info
        flow["ip_len"] = ip_len
        flow["ip_id"] = ip_id
        flow["ip_flags"] = ip_flags
        flow["ip_frag"] = ip_frag
        flow["ip_ttl"] = ip_ttl
        flow["ip_chksum"] = ip_chksum

        # Update TCP info if available
        if tcp_flags is not None:
            flow["tcp_sport"] = tcp_sport
            flow["tcp_dport"] = tcp_dport
            flow["tcp_seq"] = tcp_seq
            flow["tcp_ack"] = tcp_ack
            flow["tcp_dataofs"] = tcp_dataofs
            flow["tcp_reserved"] = tcp_reserved
            flow["tcp_flags"].append(tcp_flags)
            flow["tcp_window"] = tcp_window
            flow["tcp_chksum"] = tcp_chksum
            flow["tcp_urgptr"] = tcp_urgptr
            flow["tcp_options"] = tcp_options
            if "F" in tcp_flags: flow["fin_flag_count"] += 1
            if "S" in tcp_flags: flow["syn_flag_count"] += 1
            if "R" in tcp_flags: flow["rst_flag_count"] += 1
            if "P" in tcp_flags: flow["psh_flag_count"] += 1
            if "A" in tcp_flags: flow["ack_flag_count"] += 1
            if "U" in tcp_flags: flow["urg_flag_count"] += 1

        # Update UDP info if available
        if udp_sport is not None:
            flow["udp_sport"] = udp_sport
            flow["udp_dport"] = udp_dport
            flow["udp_len"] = udp_len
            flow["udp_chksum"] = udp_chksum

        # Update ICMP info if available
        if icmp_type is not None:
            flow["icmp_type"] = icmp_type
            flow["icmp_code"] = icmp_code
            flow["icmp_id"] = icmp_id
            flow["icmp_seq"] = icmp_seq

        # Update maximum raw payload if this packet’s payload is larger
        if raw_payload_len > flow["payload_max"]:
            flow["payload_max"] = raw_payload_len

        # Recalculate flow duration and rates
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
                "ip_src", "ip_dst", "tcp_sport", "tcp_dport", "udp_sport", "udp_dport",
                "icmp_type", "icmp_code", "packet_count", "byte_count",
                "pkt_len_max", "pkt_len_min", "payload_max",
                "flow_iat_max", "flow_iat_min", "flow_iat_mean", "flow_iat_std", 
                "flow_duration", "packets_per_second", "bytes_per_second",
                "tcp_window", "fin_flag_count", "syn_flag_count", "rst_flag_count",
                "psh_flag_count", "ack_flag_count", "urg_flag_count"
            ]])
            print("\n--------------------\n")
        else:
            print("\nNo active flows detected...\n")

# Function to export flows to a CSV file periodically
def export_to_csv():
    while True:
        time.sleep(10)  # Export every 10 seconds; adjust as needed.
        if flow_records:
            df = pd.DataFrame.from_dict(flow_records, orient='index')
            df.to_csv('active_flows.csv', index=False)
            print("Exported flows to active_flows.csv")

# Start sniffing in a separate thread
def start_sniffing():
    print(f"Starting packet capture on {NETWORK_INTERFACE}. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False, iface=NETWORK_INTERFACE)

# Start threads for display and export
display_thread = threading.Thread(target=display_flows, daemon=True)
export_thread = threading.Thread(target=export_to_csv, daemon=True)
display_thread.start()
export_thread.start()

# Start packet sniffing (blocking operation)
try:
    start_sniffing()
except KeyboardInterrupt:
    print("\nCapture stopped. Exiting...")
