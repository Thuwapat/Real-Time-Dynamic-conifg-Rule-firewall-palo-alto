import pandas as pd
import numpy as np
import random

def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_synthetic_ddos_data(num_samples=1000, ddos_ratio=0.2, random_state=42):
    np.random.seed(random_state)
    random.seed(random_state)

    # Number of DDoS samples vs. normal samples
    num_ddos = int(num_samples * ddos_ratio)
    num_normal = num_samples - num_ddos

    # Features:
    # Let's say we have features: src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, label
    data = []
    
    # Protocol categories
    protocols = ['TCP', 'UDP', 'ICMP']
    
    # Generate normal traffic
    for _ in range(num_normal):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = np.random.randint(1, 65535)
        dst_port = np.random.randint(1, 65535)
        protocol = random.choice(protocols)
        
        # For normal traffic, let's say packet_count and byte_count are in moderate ranges
        packet_count = np.random.randint(10, 200)     # moderate packet counts
        byte_count = packet_count * np.random.randint(50, 200)  # roughly some average packet sizes
        
        label = 0  # normal
        data.append([src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, label])
    
    # Generate DDoS traffic
    for _ in range(num_ddos):
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        src_port = np.random.randint(1, 65535)
        dst_port = np.random.randint(1, 65535)
        protocol = random.choice(protocols)
        
        # For DDoS traffic, let's assume packet_count and byte_count are generally higher
        packet_count = np.random.randint(500, 5000)   # higher packet counts
        byte_count = packet_count * np.random.randint(100, 400)  # generally larger total byte volume
        
        label = 1  # ddos
        data.append([src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, label])
    
    # Shuffle the data
    np.random.shuffle(data)

    columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_count', 'byte_count', 'label']
    df = pd.DataFrame(data, columns=columns)
    return df

# Example usage:
df = generate_synthetic_ddos_data(num_samples=1000, ddos_ratio=0.3)
print(df.head())
print("Distribution of labels:\n", df['label'].value_counts())
