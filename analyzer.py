"""
Network Traffic Analyzer
-------------------------
Parses packet captures (live or from .pcap files) and flags suspicious
patterns: port scans, SYN floods, and abnormal traffic volume spikes.

Author: James Gaspardo

Usage:
    # Analyze an existing pcap file
    python3 analyzer.py --pcap capture.pcap

    # Live capture (requires root/admin + a real interface)
    sudo python3 analyzer.py --live --iface eth0 --duration 60
"""

import argparse
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import rdpcap, sniff, IP, IPv6, TCP, UDP


class TrafficAnalyzer:
    def __init__(self, port_scan_threshold=15, port_scan_window=10,
                 syn_flood_threshold=100, volume_spike_multiplier=4):
        """
        port_scan_threshold : distinct destination ports from one source
                               within `port_scan_window` seconds to flag as a scan
        port_scan_window     : time window (seconds) for port scan detection
        syn_flood_threshold  : SYN packets from one source within the window
                               to flag as a possible SYN flood
        volume_spike_multiplier : how many times above the rolling average
                                   packet rate counts as a "spike"
        """
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.volume_spike_multiplier = volume_spike_multiplier

        # tracking state
        self.src_ports_seen = defaultdict(lambda: defaultdict(set))  # src -> window_bucket -> {ports}
        self.syn_counts = defaultdict(lambda: defaultdict(int))       # src -> window_bucket -> syn count
        self.packet_counts_per_window = defaultdict(int)              # window_bucket -> total packets
        self.findings = []
        self.total_packets = 0
        self.skipped_non_ip = 0

    def _bucket(self, timestamp):
        """Round a timestamp down to the nearest detection window."""
        return int(timestamp // self.port_scan_window)

    def process_packet(self, pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            # Non-IP traffic (ARP, mDNS discovery frames, etc.) - not analyzed
            self.skipped_non_ip += 1
            return

        self.total_packets += 1
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        bucket = self._bucket(ts)

        self.packet_counts_per_window[bucket] += 1

        if TCP in pkt:
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            # Track distinct destination ports per source per window -> port scan detection
            self.src_ports_seen[src][bucket].add(dport)
            ports_this_window = self.src_ports_seen[src][bucket]
            if len(ports_this_window) == self.port_scan_threshold:
                self.findings.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "source": src,
                    "detail": f"{src} touched {len(ports_this_window)}+ distinct ports "
                              f"within {self.port_scan_window}s (target(s) include {dst})",
                    "time": self._fmt_time(ts)
                })

            # SYN flag only, no ACK -> a "SYN" packet (connection attempt)
            if flags == "S":
                self.syn_counts[src][bucket] += 1
                if self.syn_counts[src][bucket] == self.syn_flood_threshold:
                    self.findings.append({
                        "type": "POSSIBLE_SYN_FLOOD",
                        "severity": "HIGH",
                        "source": src,
                        "detail": f"{src} sent {self.syn_counts[src][bucket]}+ SYN packets "
                                  f"within {self.port_scan_window}s (target {dst})",
                        "time": self._fmt_time(ts)
                    })

        elif UDP in pkt:
            dport = pkt[UDP].dport
            self.src_ports_seen[src][bucket].add(dport)

    def _fmt_time(self, ts):
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, OverflowError, ValueError):
            return "unknown"

    def detect_volume_spikes(self):
        """After processing, check for windows with abnormally high traffic."""
        counts = list(self.packet_counts_per_window.values())
        if len(counts) < 2:
            return
        avg = sum(counts) / len(counts)
        if avg == 0:
            return
        for bucket, count in self.packet_counts_per_window.items():
            if count > avg * self.volume_spike_multiplier and count > 20:
                self.findings.append({
                    "type": "VOLUME_SPIKE",
                    "severity": "MEDIUM",
                    "source": "N/A",
                    "detail": f"Traffic spike: {count} packets in window "
                              f"(avg is {avg:.1f}/window, ~{count/avg:.1f}x normal)",
                    "time": f"window #{bucket}"
                })

    def analyze_pcap(self, path):
        print(f"[*] Reading pcap file: {path}")
        packets = rdpcap(path)
        print(f"[*] Loaded {len(packets)} packets. Analyzing...")
        for pkt in packets:
            self.process_packet(pkt)
        self.detect_volume_spikes()
        self.report()

    def analyze_live(self, iface, duration):
        print(f"[*] Starting live capture on {iface} for {duration}s (requires root)...")
        sniff(iface=iface, timeout=duration, prn=self.process_packet, store=False)
        self.detect_volume_spikes()
        self.report()

    def report(self):
        print("\n" + "=" * 60)
        print("TRAFFIC ANALYSIS REPORT")
        print("=" * 60)
        print(f"Total packets analyzed: {self.total_packets}")
        print(f"Non-IP packets skipped (ARP/mDNS/etc.): {self.skipped_non_ip}")
        print(f"Findings: {len(self.findings)}")
        print("-" * 60)

        if not self.findings:
            print("No suspicious activity detected.")
        else:
            # de-duplicate identical repeated findings, keep first occurrence
            seen = set()
            for f in self.findings:
                key = (f["type"], f["source"], f["time"])
                if key in seen:
                    continue
                seen.add(key)
                print(f"[{f['severity']}] {f['type']}")
                print(f"    Source : {f['source']}")
                print(f"    Detail : {f['detail']}")
                print(f"    Time   : {f['time']}")
                print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--pcap", help="Path to a .pcap/.pcapng file to analyze")
    parser.add_argument("--live", action="store_true", help="Capture live traffic (requires root)")
    parser.add_argument("--iface", help="Network interface for live capture (e.g. eth0, en0)")
    parser.add_argument("--duration", type=int, default=60, help="Live capture duration in seconds")
    parser.add_argument("--port-scan-threshold", type=int, default=15,
                         help="Distinct ports from one source to flag as a scan")
    parser.add_argument("--window", type=int, default=10, help="Detection window in seconds")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer(
        port_scan_threshold=args.port_scan_threshold,
        port_scan_window=args.window
    )

    if args.pcap:
        analyzer.analyze_pcap(args.pcap)
    elif args.live:
        if not args.iface:
            parser.error("--live requires --iface <interface name>")
        analyzer.analyze_live(args.iface, args.duration)
    else:
        parser.error("Specify either --pcap <file> or --live --iface <interface>")


if __name__ == "__main__":
    main()