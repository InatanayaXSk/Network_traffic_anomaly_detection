"""
Backend module for network anomaly detection.

This part of the application is responsible for capturing and detecting anomalies
in network traffic using:
- pyshark (packet capture)
- pandas (data manipulation)
- sklearn (machine learning)

Workflow:
1. Capture packets using pyshark
2. Extract features using pandas & logic
3. Feed processed data into a pre-trained ML model for anomaly detection
"""

import pyshark
import time
import pandas as pd
import logging
from collections import defaultdict, deque
import hashlib
import json
from joblib import load
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import re
from Packet_anomaly import generate_anomalous_packets

# Load trained model
model = load('AnomalyDetectionModel.joblib')

def safe_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0

# Track metrics
packet_rate = defaultdict(lambda: {'packet_count': 0, 'start_time': time.time(), 'end_time': time.time()})
failed_connections = defaultdict(lambda: {'syn_count': 0, 'syn_ack_count': 0})
port_diversity = defaultdict(set)
protocol_distribution = defaultdict(int)
connection_attempts = defaultdict(deque)

# Anomaly tracking
anomalies_count = 1
anomalies_by_type = defaultdict(int)
anomaly_ips_by_type = defaultdict(set)
anomalies_last_seen = {}

# Feature extractors
def update_packet_rate(src_ip, current_time):
    packet_rate[src_ip]['packet_count'] += 1
    packet_rate[src_ip]['end_time'] = current_time
    duration = packet_rate[src_ip]['end_time'] - packet_rate[src_ip]['start_time']
    return packet_rate[src_ip]['packet_count'] / duration if duration > 0 else 0

def update_syn_ack_ratio(src_ip, tcp_flags):
    if isinstance(tcp_flags, str) and 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
        failed_connections[src_ip]['syn_count'] += 1
    if isinstance(tcp_flags, str) and 'SYN-ACK' in tcp_flags:
        failed_connections[src_ip]['syn_ack_count'] += 1
    syn = failed_connections[src_ip]['syn_count']
    syn_ack = failed_connections[src_ip]['syn_ack_count']
    return syn_ack / syn if syn > 0 else 0

def update_unsuccessful_connections(src_ip, tcp_flags):
    if isinstance(tcp_flags, str) and 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
        failed_connections[src_ip]['syn_count'] += 1
    if isinstance(tcp_flags, str) and 'SYN-ACK' in tcp_flags:
        failed_connections[src_ip]['syn_ack_count'] += 1
    syn = failed_connections[src_ip]['syn_count']
    syn_ack = failed_connections[src_ip]['syn_ack_count']
    failed = syn - syn_ack
    return failed / syn if syn > 0 else 0

def update_port_diversity_func(src_ip, dst_port):
    port_diversity[src_ip].add(dst_port)
    return len(port_diversity[src_ip])

def update_protocol_distribution_func(proto):
    if proto == 1:
        protocol_distribution['TCP'] += 1
    elif proto == 2:
        protocol_distribution['UDP'] += 1
    else:
        protocol_distribution['Other'] += 1

# ML Prediction
def checkAnomaly(data):
    df = pd.DataFrame([data])
    df.drop(columns=[col for col in ['Source IP', 'Destination IP'] if col in df.columns], inplace=True)
    for col in df.select_dtypes(include=['object']):
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
    return model.predict(df)[0]

# Save statistics
def save_json(counter):
    json_data = {
        "total_packets": int(counter),
        "total_anomalies": int(anomalies_count),
        "anomalies_by_type": {str(k): int(v) for k, v in anomalies_by_type.items()},
        "anomaly_ips": {str(k): list(map(str, v)) for k, v in anomaly_ips_by_type.items()},
        "protocol_distribution": {str(k): int(v) for k, v in protocol_distribution.items()},
        "anomalies_last_seen": {str(k): datetime.fromtimestamp(ts).isoformat() for k, ts in anomalies_last_seen.items()}
    }
    with open("network_traffic_summary.json", 'w') as f:
        json.dump(json_data, f, indent=4)

# Optional utility to extract & save JSON from mixed text
def extract_and_save_json(text, output_filename):
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found.")
    data = json.loads(match.group(0).strip())
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump({k: data[k] for k in ["en", "ku", "ar"]}, f, ensure_ascii=False, indent=4)

# Main capture function
anomalies_count = 0
anomalies_by_type = {1: 0, 2: 0, 3: 0}
anomaly_ips_by_type = {1: set(), 2: set(), 3: set()}
anomalies_last_seen = {}

last_saved_counter = -1  # To debounce save_json

def capture(interface="wlp0s20f3", duration=3000):
    print("Running...")
    cap = pyshark.LiveCapture(interface=interface)
    start_time = time.time()
    sessions = {}
    counter = 0

    logging.basicConfig(level=logging.ERROR, filename='packet_errors.log')

    anomalous_packets = generate_anomalous_packets()
    anomaly_injection_interval = 200  # Less frequent

    try:
        for packet in cap:
            current_time = time.time()
            if current_time - start_time > duration:
                print("Duration reached, exiting...")
                break

            counter += 1

            # Inject anomalies less frequently for realism
            if counter % anomaly_injection_interval == 0:
                print("[DEBUG] Injecting Anomalous Packets...")
                for anomalous_packet in anomalous_packets:
                    process_packet(anomalous_packet, sessions, counter, current_time)

            # Process the captured packet
            process_packet(packet, sessions, counter, current_time)

    except (EOFError, KeyboardInterrupt):
        print("Capture stopped.")
    finally:
        cap.close()
        save_json(counter)
        print("Capture closed.")

def process_packet(packet, sessions, counter, current_time):
    global anomalies_count, anomalies_by_type, anomaly_ips_by_type, anomalies_last_seen, last_saved_counter

    try:
        src_ip = dst_ip = flags = tcp_flags = ''
        ttl = src_port = dst_port = 0
        checksum = ''
        protocol = 0
        total_length = payload_size = unsuccessful_conn = 0

        # Handle simulated vs live packet
        if isinstance(packet, dict):
            ip_layer = packet.get('ip', {})
            src_ip = ip_layer.get('src', '0.0.0.0')
            dst_ip = ip_layer.get('dst', '0.0.0.0')
            total_length = safe_int(ip_layer.get('len', 0))
            flags = ip_layer.get('flags', '')
            ttl = safe_int(ip_layer.get('ttl', 0))
            checksum = ip_layer.get('checksum', '')
            proto_str = packet.get('transport_layer', 'Unknown')
            tcp_layer = packet.get('tcp')
            udp_layer = packet.get('udp')
            payload_size = packet.get('payload_size', 0)

            if proto_str == "TCP" and tcp_layer:
                protocol = 1
                tcp_flags = tcp_layer.get('flags', '')
                tcp_header_len = safe_int(tcp_layer.get('hdr_len', 0))
                src_port = safe_int(tcp_layer.get('srcport', 0))
                dst_port = safe_int(tcp_layer.get('dstport', 0))
                unsuccessful_conn = update_unsuccessful_connections(src_ip, tcp_flags)
            elif proto_str == "UDP" and udp_layer:
                protocol = 2
                src_port = safe_int(udp_layer.get('srcport', 0))
                dst_port = safe_int(udp_layer.get('dstport', 0))
                if 'payload' in udp_layer and isinstance(udp_layer['payload'], bytes):
                    payload_size = len(udp_layer['payload'])
            else:
                protocol = packet.get('protocol_number', 0)

        else:
            if hasattr(packet, 'ip'):
                ip_layer = packet.ip
                src_ip = getattr(ip_layer, 'src', '0.0.0.0')
                dst_ip = getattr(ip_layer, 'dst', '0.0.0.0')
                total_length = safe_int(getattr(ip_layer, 'len', 0))
                flags = getattr(ip_layer, 'flags', '')
                ttl = safe_int(getattr(ip_layer, 'ttl', 0))
                checksum = getattr(ip_layer, 'checksum', '')

            proto_str = str(getattr(packet, 'transport_layer', 'Unknown'))
            if proto_str == "TCP":
                protocol = 1
                tcp_flags = str(getattr(packet.tcp, 'flags', ''))
                tcp_header_len = safe_int(getattr(packet.tcp, 'hdr_len', 0))
                src_port = safe_int(getattr(packet.tcp, 'srcport', 0))
                dst_port = safe_int(getattr(packet.tcp, 'dstport', 0))
                payload_size = total_length - tcp_header_len
                unsuccessful_conn = update_unsuccessful_connections(src_ip, tcp_flags)
            elif proto_str == "UDP":
                protocol = 2
                src_port = safe_int(getattr(packet.udp, 'srcport', 0))
                dst_port = safe_int(getattr(packet.udp, 'dstport', 0))
                if hasattr(packet.udp, 'payload'):
                    payload_size = len(packet.udp.payload.binary_value)

        session_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        if session_key not in sessions:
            sessions[session_key] = {'start_time': current_time, 'packet_count': 0, 'byte_count': 0}
        sessions[session_key]['packet_count'] += 1
        sessions[session_key]['byte_count'] += total_length

        session_id = int(hashlib.sha256(f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}".encode()).hexdigest(), 16) % (10**8)

        features = {
            "Session ID": session_id,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Protocol": protocol,
            "Total Length": total_length,
            "TTL": ttl,
            "Checksum": checksum,
            "Flags": flags,
            "TCP Flags": tcp_flags,
            "Payload Size": payload_size,
            "Packet Rate": update_packet_rate(src_ip, current_time),
            "SYN-ACK Ratio": update_syn_ack_ratio(src_ip, tcp_flags),
            "Port Diversity": update_port_diversity_func(src_ip, dst_port),
            "Retransmissions": 0,
            "Unsuccessful Connections": unsuccessful_conn,
            "Number of Packets": sessions[session_key]['packet_count'],
            "Byte Count": sessions[session_key]['byte_count'],
        }

        update_protocol_distribution_func(protocol)

        anomaly = checkAnomaly(features)
        if anomaly > 0:
            anomalies_count += 1
            anomalies_by_type[anomaly] += 1
            anomaly_ips_by_type[anomaly].add(src_ip)
            anomalies_last_seen[anomaly] = current_time
            
        print(f"[ANOMALY] Type: {anomaly} | Source IP: {src_ip} | Checksum: {checksum}")

            # Avoid saving every single time
        if counter != last_saved_counter:
            save_json(counter)
            last_saved_counter = counter

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Run capture
capture()
