# Network Traffic Analyzer

A Python tool that parses network traffic and flags suspicious patterns:
port scans, SYN floods, and abnormal traffic volume spikes.

## Setup

```bash
pip install scapy
```

On live-capture mode you'll also need:
- **Linux/macOS:** run with `sudo` (raw socket access requires root)
- **Windows:** install [Npcap](https://npcap.com/) and run as Administrator

## Usage

### 1. Try it on the included test capture (no setup needed)

```bash
python3 analyzer.py --pcap test_capture.pcap
```

This runs against a synthetic pcap containing normal traffic plus a
simulated port scan and SYN flood, so you can see the detection working
immediately.

### 2. Generate a fresh synthetic capture

```bash
python3 generate_test_pcap.py
```

Creates `test_capture.pcap` with randomized normal + attack traffic
(useful if you want to tweak the attack patterns in the script and
re-test).

### 3. Analyze a real pcap file

Capture traffic with Wireshark or `tcpdump`, then:

```bash
python3 analyzer.py --pcap your_capture.pcap
```

### 4. Live capture on your own machine

```bash
sudo python3 analyzer.py --live --iface eth0 --duration 60
```

Replace `eth0` with your interface name (`en0` on macOS, check
`ipconfig`/`Get-NetAdapter` on Windows). **Only run this against
networks you own or have explicit permission to monitor.**

## How detection works

- **Port scan:** flags a source IP that touches 15+ distinct destination
  ports within a 10-second window (both thresholds are configurable via
  `--port-scan-threshold` and `--window`).
- **SYN flood:** flags a source sending 100+ TCP SYN packets within the
  same window with no completed handshake — a classic DoS pattern.
- **Volume spike:** after processing, compares packet counts per window
  against the rolling average and flags windows running 4x+ above normal.

## For your resume / interview talking points

- Explain the tradeoffs of your thresholds (why 15 ports / 10s, not 5/60s)
  and how you'd tune them to reduce false positives on a real network.
- Talk through why SYN-without-ACK is the signal for a flood, and what a
  legitimate connection's flag sequence looks like by comparison.
- Be ready to discuss what this tool *doesn't* catch (e.g., slow/low-rate
  scans designed to evade the window, or encrypted payload inspection).

## Legal note

Only run live capture against networks and systems you own or are
explicitly authorized to monitor. Unauthorized packet sniffing may
violate the Computer Fraud and Abuse Act (US) or equivalent laws
elsewhere.
