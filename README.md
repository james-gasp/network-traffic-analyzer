# Network Traffic Analyzer

A Python tool that parses network traffic (`.pcap` files or live capture) and flags suspicious patterns like port scans, SYN floods, and abnormal traffic volume spikes using sliding fixed time-window detection.

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

## Known limitations

- **Reply traffic can look like scan traffic.** The tool currently checks "does one source touch many ports quickly" without distinguishing between a scan's outbound probes and a target's inbound replies. A production version would need to track TCP connection state (who initiated the handshake) rather than just counting distinct ports.
- **Fixed time windows can be evaded.** A slow scan spread across hours would fall below the per-window threshold entirely.
- **No encrypted payload inspection** — this only looks at headers/metadata (IPs, ports, flags), not packet contents.
- **Thresholds are static**, not adaptive to a specific network's normal baseline.

## Legal note

Only run live capture or scans against networks and systems you own or are explicitly authorized to test. Unauthorized packet sniffing or scanning may violate the Computer Fraud and Abuse Act (US) or equivalent laws elsewhere.
