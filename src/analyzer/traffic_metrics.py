from collections import defaultdict, Counter
from datetime import datetime, timezone
from scapy.all import rdpcap, TCP, UDP, ICMP, IP

PCAP_FILE = "data/captures/port-scan-test.pcap"

packets = rdpcap(PCAP_FILE)
protocols = Counter()
source_ips = Counter()
destination_ports = Counter()

CLIENT_IP = "172.26.0.3"
SERVER_IP = "172.26.0.2"

for packet in packets:
    if not packet.haslayer(IP):
        continue

    if packet[IP].src != CLIENT_IP:
        continue

    if packet[IP].dst != SERVER_IP:
        continue

    if packet.haslayer(TCP):
        destination_ports[packet[TCP].dport] += 1

    elif packet.haslayer(UDP):
        destination_ports[packet[UDP].dport] += 1

for packet in packets:
    if packet.haslayer(IP):
        source_ips[packet[IP].src] += 1

for packet in packets:
    if packet.haslayer(TCP):
        protocols["TCP"] += 1
    elif packet.haslayer(UDP):
        protocols["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocols["ICMP"] += 1
    else:
        protocols["OTHER"] += 1

metrics = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0
})

for packet in packets:
    second = int(float(packet.time))

    metrics[second]["packets"] += 1
    metrics[second]["bytes"] += len(packet)

print("Traffic Metrics")
print("-" * 45)
print(f"{'Time (UTC)':<15} {'Packets':<10} {'Bytes':<10}")

for second, data in sorted(metrics.items()):
    timestamp = datetime.fromtimestamp(
        second, timezone.utc
    ).strftime("%H:%M:%S")

    print(
        f"{timestamp:<15} "
        f"{data['packets']:<10} "
        f"{data['bytes']:<10}"
    )

print("\nProtocol Distribution")
print("-" * 30)

for protocol, count in protocols.most_common():
    percentage = (count / len(packets)) * 100
    print(f"{protocol:<10} {count:<10} {percentage:.2f}%")

print("\nSource IP Distribution")
print("-" * 30)

for ip, count in source_ips.most_common():
    percentage = (count / len(packets)) * 100
    print(f"{ip:<18} {count:<10} {percentage:.2f}%")

print("\nDestination Port Distribution")
print("-" * 35)

total_scanned_packets = sum(destination_ports.values())

for port, count in destination_ports.most_common():
    percentage = (count / total_scanned_packets) * 100
    print(f"Port {port:<10} {count:<10} {percentage:.2f}%")