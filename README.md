# Basic Network Sniffer

**Rhombix Technologies — Cyber Security Internship (Month 1, Task 1)**

## Overview
A Python-based network sniffer that captures live traffic on a network interface
and analyzes each packet, showing:
- Source and destination IP addresses
- Protocol (TCP, UDP, ICMP, or other)
- Source and destination ports (for TCP/UDP)
- TCP flags (SYN, ACK, etc.)
- A short readable preview of the packet payload (if present)

At the end of the capture, it prints a summary with a breakdown of packet counts
by protocol.

## How it works
This project helps understand how data flows on a network by using **Scapy**,
a Python library for packet manipulation, to:
1. Open a live capture on a chosen network interface
2. Parse each packet's IP layer to identify source/destination
3. Detect the transport-layer protocol (TCP/UDP/ICMP)
4. Extract port numbers and any raw payload bytes
5. Print a formatted, timestamped log line per packet

## Requirements
- Python 3.8+
- [Scapy](https://scapy.net/)
- Administrator/root privileges (required for raw packet capture)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Sniff on the default interface (Ctrl+C to stop)
sudo python3 sniffer.py

# Sniff on a specific interface
sudo python3 sniffer.py -i eth0

# Stop automatically after 50 packets
sudo python3 sniffer.py -c 50

# Apply a BPF filter (only capture HTTP traffic)
sudo python3 sniffer.py -f "tcp port 80"

# Save captured output to a log file as well as printing it
sudo python3 sniffer.py -l capture_log.txt
```

### Windows users
On Windows, install [Npcap](https://npcap.com/) first (Scapy depends on it for
packet capture), then run the script from an Administrator command prompt.

## Sample Output
```
[*] Starting Basic Network Sniffer
[*] For educational use on networks you own or are authorized to monitor.
[*] Interface : eth0
[*] Filter    : tcp port 80
[*] Count     : unlimited (Ctrl+C to stop)
--------------------------------------------------
[14:22:01] 192.168.1.5 -> 142.250.183.14 | Protocol: TCP | Src Port: 51322 -> Dst Port: 80 | Flags: S
[14:22:01] 142.250.183.14 -> 192.168.1.5 | Protocol: TCP | Src Port: 80 -> Dst Port: 51322 | Flags: SA

==================================================
Capture Summary
==================================================
Total packets captured : 2
TCP packets            : 2
UDP packets            : 0
ICMP packets           : 0
Other/Non-IP packets   : 0
==================================================
```

## Ethical Use Notice
This tool is built strictly for **educational purposes** as part of the
Rhombix Technologies internship. Only run it on networks you own or have
explicit authorization to monitor. Capturing traffic on networks without
permission may be illegal in your jurisdiction.

## Author
Touqeer — BS Information Technology, University of Management and Technology (UMT), Lahore
Rhombix Technologies Cyber Security Internship, Month 1
