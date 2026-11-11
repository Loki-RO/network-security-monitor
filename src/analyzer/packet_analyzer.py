from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter, defaultdict

# Lokasi file PCAP
PCAP_FILE = "data/captures/http-test.pcap"


def analyze_packets():
    # Membaca seluruh paket dari file PCAP
    packets = rdpcap(PCAP_FILE)
    syn_scan_ports = defaultdict(set)

    # Menghitung jumlah setiap protokol
    protocol_counts = Counter()
    source_ip_counts = Counter()
    destination_port_counts = Counter()
    tcp_flag_counts = Counter()

    print("===== NETWORK PACKET ANALYZER =====\n")
    print(f"Total Packets: {len(packets)}\n")

    for index, packet in enumerate(packets, start=1):

        # Memastikan paket memiliki layer IP
        if packet.haslayer(IP):
            ip = packet[IP]

            source_ip = ip.src
            destination_ip = ip.dst
            source_ip_counts[source_ip] += 1

            # Memeriksa apakah paket menggunakan TCP
            if packet.haslayer(TCP):
                tcp = packet[TCP]

                protocol = "TCP"
                source_port = tcp.sport
                destination_port = tcp.dport
                flags = str(tcp.flags)
                destination_port_counts[destination_port] += 1
                tcp_flag_counts[flags] += 1

                # Mendeteksi paket SYN tanpa ACK
                if tcp.flags & 0x02 and not tcp.flags & 0x10:
                    syn_scan_ports[source_ip].add(destination_port)

            # Memeriksa apakah paket menggunakan UDP
            elif packet.haslayer(UDP):
                udp = packet[UDP]

                protocol = "UDP"
                source_port = udp.sport
                destination_port = udp.dport
                flags = "-"

            else:
                protocol = "OTHER"
                source_port = "-"
                destination_port = "-"
                flags = "-"

            protocol_counts[protocol] += 1

            print(f"Packet #{index}")
            print(f"  Source IP      : {source_ip}")
            print(f"  Destination IP : {destination_ip}")
            print(f"  Source Port    : {source_port}")
            print(f"  Destination Port: {destination_port}")
            print(f"  Protocol       : {protocol}")
            print(f"  TCP Flags      : {flags}")
            print("-" * 45)

    # Menampilkan ringkasan protokol
    print("\n===== PROTOCOL SUMMARY =====")
    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count}")

    print("\n===== SOURCE IP SUMMARY =====")
    for ip, count in source_ip_counts.most_common():
        print(f"{ip}: {count} packets")

    print("\n===== DESTINATION PORT SUMMARY =====")
    for port, count in destination_port_counts.most_common():
        print(f"Port {port}: {count} packets")

    print("\n===== TCP FLAGS SUMMARY =====")
    for flag, count in tcp_flag_counts.most_common():
        print(f"{flag}: {count} packets")

    print("\n===== PORT SCAN DETECTION =====")

    THRESHOLD = 10
    for ip, ports in syn_scan_ports.items():
        port_count = len(ports)

        print(f"Source IP: {ip}")
        print(f"Unique destination ports: {port_count}")

        if port_count >= THRESHOLD:
            print("[ALERT] Possible port scanning detected!")
        else:
            print("[INFO] No port scanning detected.")

        print(f"Scanned ports: {sorted(ports)}")

if __name__ == "__main__":
    analyze_packets()