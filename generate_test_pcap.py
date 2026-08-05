"""
Generates a synthetic .pcap file containing a mix of normal traffic and
simulated attack patterns (port scan, SYN flood, traffic spike) so you
can test analyzer.py without needing real attack traffic.

Usage:
    python3 generate_test_pcap.py
    # creates test_capture.pcap in the current directory
"""

import random
import time
from scapy.all import IP, TCP, UDP, wrpcap


def normal_traffic(start_time, count=150):
    """Simulate everyday browsing/streaming traffic between a handful of hosts."""
    packets = []
    normal_hosts = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    common_ports = [443, 80, 53, 22]
    t = start_time
    for _ in range(count):
        src = random.choice(normal_hosts)
        dst = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
        pkt = IP(src=src, dst=dst) / TCP(
            sport=random.randint(1024, 65535),
            dport=random.choice(common_ports),
            flags="A"
        )
        t += random.uniform(0.05, 0.3)
        pkt.time = t
        packets.append(pkt)
    return packets, t


def port_scan_traffic(start_time, attacker="10.0.0.66", target="192.168.1.50", count=40):
    """Simulate a single source rapidly probing many ports on one target (port scan)."""
    packets = []
    t = start_time
    for port in range(1, count + 1):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )
        t += random.uniform(0.01, 0.05)  # fast, tight timing typical of a scan
        pkt.time = t
        packets.append(pkt)
    return packets, t


def syn_flood_traffic(start_time, attacker="10.0.0.77", target="192.168.1.50", count=150):
    """Simulate a SYN flood: many SYNs to the same port with no completed handshake."""
    packets = []
    t = start_time
    for _ in range(count):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags="S"
        )
        t += random.uniform(0.001, 0.01)
        pkt.time = t
        packets.append(pkt)
    return packets, t


def main():
    start_time = time.time() - 300  # pretend capture started 5 min ago
    all_packets = []

    print("[*] Generating normal baseline traffic...")
    normal_pkts, t = normal_traffic(start_time)
    all_packets += normal_pkts

    print("[*] Injecting simulated port scan...")
    scan_pkts, t2 = port_scan_traffic(t + 5)
    all_packets += scan_pkts

    print("[*] Injecting more normal traffic...")
    more_normal, t3 = normal_traffic(t2 + 10, count=60)
    all_packets += more_normal

    print("[*] Injecting simulated SYN flood...")
    flood_pkts, t4 = syn_flood_traffic(t3 + 5)
    all_packets += flood_pkts

    all_packets.sort(key=lambda p: p.time)

    out_path = "test_capture.pcap"
    wrpcap(out_path, all_packets)
    print(f"[+] Wrote {len(all_packets)} packets to {out_path}")
    print("    - normal traffic (baseline)")
    print("    - simulated port scan from 10.0.0.66 -> 192.168.1.50")
    print("    - simulated SYN flood from 10.0.0.77 -> 192.168.1.50")


if __name__ == "__main__":
    main()
