
import csv
import os
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

CLIENT_IP = "172.26.0.3"
SERVER_IP = "172.26.0.2"

CAPTURES = [
    ("data/captures/http-test.pcap", "normal"),
    ("data/captures/port-scan-test.pcap", "port_scan"),
]

OUTPUT_FILE = "data/metrics/traffic_features.csv"


def extract_features(pcap_file, label):
    packets = rdpcap(pcap_file)

    metrics = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "other_count": 0,
        "source_ips": set(),
        "destination_ports": set(),
        "client_packets": 0,
        "server_packets": 0,
    })

    for packet in packets:
        second = int(float(packet.time))
        data = metrics[second]

        data["packet_count"] += 1
        data["byte_count"] += len(packet)

        if packet.haslayer(TCP):
            data["tcp_count"] += 1
        elif packet.haslayer(UDP):
            data["udp_count"] += 1
        elif packet.haslayer(ICMP):
            data["icmp_count"] += 1
        else:
            data["other_count"] += 1

        if not packet.haslayer(IP):
            continue

        data["source_ips"].add(packet[IP].src)

        if packet[IP].src == CLIENT_IP and packet[IP].dst == SERVER_IP:
            data["client_packets"] += 1

            if packet.haslayer(TCP):
                data["destination_ports"].add(packet[TCP].dport)
            elif packet.haslayer(UDP):
                data["destination_ports"].add(packet[UDP].dport)

        elif packet[IP].src == SERVER_IP and packet[IP].dst == CLIENT_IP:
            data["server_packets"] += 1

    rows = []

    for second, data in sorted(metrics.items()):
        timestamp = datetime.fromtimestamp(
            second, timezone.utc
        ).isoformat()

        rows.append({
            "timestamp": timestamp,
            "packet_count": data["packet_count"],
            "byte_count": data["byte_count"],
            "tcp_count": data["tcp_count"],
            "udp_count": data["udp_count"],
            "icmp_count": data["icmp_count"],
            "other_count": data["other_count"],
            "unique_source_ips": len(data["source_ips"]),
            "client_packets": data["client_packets"],
            "server_packets": data["server_packets"],
            "unique_destination_ports": len(data["destination_ports"]),
            "label": label,
        })

    return rows


all_rows = []

for pcap_file, label in CAPTURES:
    print(f"Processing: {pcap_file}")

    rows = extract_features(pcap_file, label)
    all_rows.extend(rows)

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=all_rows[0].keys()
    )
    writer.writeheader()
    writer.writerows(all_rows)

print(f"\nDataset saved to: {OUTPUT_FILE}")
print(f"Total samples: {len(all_rows)}")
