# Network Traffic Analyzer

A Python tool that parses network traffic (`.pcap` files or live capture) and flags suspicious patterns like port scans, SYN floods, and abnormal traffic volume spikes using sliding fixed time-window detection.

## Why I built this

I wanted hands on experience with packet level network analysis. This project covers protocol fundamentals (TCP flags, IP addressing), scripting against real capture data, and maybe more importantly the debugging process of validating a security tool against real traffic instead of trusting that it works.

## How it works

- Reads packets via [Scapy](https://scapy.net/), either from a `.pcap`/`.pcapng` file or a live interface capture.
- Groups traffic into fixed-length time windows (default 10s).
- **Port scan detection:** flags a source IP that touches 15+ distinct destination ports within one window.
- **SYN flood detection:** flags a source sending 100+ TCP SYN packets (no completed handshake) within one window.
- **Volume spike detection:** compares packet counts per window against the rolling average, flags windows running 4x+ above normal.

## Setup

```bash
pip install scapy
```

Live capture requires elevated privileges (root/sudo on Linux/macOS, Administrator + [Npcap](https://npcap.com/) on Windows).

## Usage

```bash
# Analyze a pcap file
python3 analyzer.py --pcap capture.pcap

# Generate a synthetic test capture (normal traffic + simulated attacks)
python3 generate_test_pcap.py
python3 analyzer.py --pcap test_capture.pcap

# Live capture (needs root/admin)
sudo python3 analyzer.py --live --iface eth0 --duration 60
```

## Testing & validation

I tested this in three stages, each catching different problems:

**1. Synthetic data** — generated a pcap with known injected attacks (port scan + SYN flood mixed into normal traffic). The tool correctly flagged both with zero false positives.

**2. Real baseline traffic** — captured my own normal browsing traffic with Wireshark and ran the analyzer against it. This surfaced a real bug: only 225 of 19,818 packets were being analyzed. The tool was silently ignoring all IPv6 traffic, which turned out to be the majority of my real-world traffic. Fixed by adding IPv6 support alongside IPv4.

**3. Real attack traffic** — used Nmap to scan a live target on my network (my router) while capturing with Wireshark, then ran the analyzer against that capture. Result:

```
Total packets analyzed: 9315
Non-IP packets skipped (ARP/mDNS/etc.): 21
Findings: 3
------------------------------------------------------------
[HIGH] PORT_SCAN
    Source : 10.0.0.142
    Detail : 10.0.0.142 touched 15+ distinct ports within 10s (target(s) include 10.0.0.1)
------------------------------------------------------------
[HIGH] PORT_SCAN
    Source : 10.0.0.1
    Detail : 10.0.0.1 touched 15+ distinct ports within 10s (target(s) include 10.0.0.142)
------------------------------------------------------------
[HIGH] POSSIBLE_SYN_FLOOD
    Source : 10.0.0.142
    Detail : 10.0.0.142 sent 100+ SYN packets within 10s (target 10.0.0.1)
------------------------------------------------------------
```

The first and third findings are the actual Nmap scan being correctly detected. The second is worth explaining: it's the **router's replies** to my scan (RST/ACK packets from many different ports as it rejected each connection attempt) getting misidentified as the router scanning me back.

## Known limitations

- **Reply traffic can look like scan traffic.** The tool currently checks "does one source touch many ports quickly" without distinguishing between a scan's outbound probes and a target's inbound replies. A production version would need to track TCP connection state (who initiated the handshake) rather than just counting distinct ports.
- **Fixed time windows can be evaded.** A slow scan spread across hours would fall below the per-window threshold entirely.
- **No encrypted payload inspection** — this only looks at headers/metadata (IPs, ports, flags), not packet contents.
- **Thresholds are static**, not adaptive to a specific network's normal baseline.

## Legal note

Only run live capture or scans against networks and systems you own or are explicitly authorized to test. Unauthorized packet sniffing or scanning may violate the Computer Fraud and Abuse Act (US) or equivalent laws elsewhere.
