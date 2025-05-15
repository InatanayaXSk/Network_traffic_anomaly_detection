import random
import time

def generate_anomalous_packets():
    """
    Generate a list of simulated anomalous packets as dicts
    mimicking minimal pyshark packet interface needed by capture().
    """
    anomalous_packets = []

    # 1. SYN Flood attack simulation (many SYN no ACK)
    src_ip_syn_flood = "192.168.1.100"
    dst_ip_syn_flood = "10.0.0.5"
    for port in range(1000, 1010):
        anomalous_packets.append({
            'ip': {'src': src_ip_syn_flood, 'dst': dst_ip_syn_flood, 'len': 60, 'flags': '', 'ttl': 64, 'checksum': 'abc123'},
            'transport_layer': 'TCP',
            'tcp': {'flags': 'SYN', 'hdr_len': 20, 'srcport': 12345, 'dstport': port},
            'udp': None,
            'payload_size': 40,
        })

    # 2. Port scanning (single IP hitting many ports rapidly)
    src_ip_scan = "192.168.1.101"
    dst_ip_scan = "10.0.0.10"
    for port in range(2000, 2020):
        anomalous_packets.append({
            'ip': {'src': src_ip_scan, 'dst': dst_ip_scan, 'len': 52, 'flags': '', 'ttl': 64, 'checksum': 'def456'},
            'transport_layer': 'TCP',
            'tcp': {'flags': 'SYN', 'hdr_len': 20, 'srcport': random.randint(1024, 65535), 'dstport': port},
            'udp': None,
            'payload_size': 32,
        })

    # 3. Unusual protocol number (simulate protocol 99 unknown)
    src_ip_unusual_proto = "192.168.1.102"
    dst_ip_unusual_proto = "10.0.0.15"
    anomalous_packets.append({
        'ip': {'src': src_ip_unusual_proto, 'dst': dst_ip_unusual_proto, 'len': 70, 'flags': '', 'ttl': 64, 'checksum': 'ghi789'},
        'transport_layer': 'Unknown',
        'tcp': None,
        'udp': None,
        'payload_size': 60,
        'protocol_number': 99  # unusual
    })

    # 4. Large payload anomaly (unusually large payload in UDP)
    src_ip_large_payload = "192.168.1.103"
    dst_ip_large_payload = "10.0.0.20"
    anomalous_packets.append({
        'ip': {'src': src_ip_large_payload, 'dst': dst_ip_large_payload, 'len': 1500, 'flags': '', 'ttl': 64, 'checksum': 'jkl012'},
        'transport_layer': 'UDP',
        'tcp': None,
        'udp': {'srcport': 54321, 'dstport': 53, 'payload': bytes(1400)},  # large payload
        'payload_size': 1400,
    })

    return anomalous_packets
