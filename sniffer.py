#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Rhombix Technologies - Cyber Security Internship (Month 1, Task 1)

Description:
    Captures live network traffic on a chosen interface and analyzes each
    packet: source/destination IP, protocol, source/destination ports
    (for TCP/UDP), and a short preview of the raw payload (if any).

Requirements:
    pip install scapy
    (Must be run with administrator/root privileges to capture packets)

Usage:
    sudo python3 sniffer.py                     # sniff on default interface
    sudo python3 sniffer.py -i eth0              # sniff on a specific interface
    sudo python3 sniffer.py -c 50                # stop after 50 packets
    sudo python3 sniffer.py -f "tcp port 80"      # apply a BPF filter
    sudo python3 sniffer.py -l capture_log.txt    # save output to a log file
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)

# Global counters for the summary shown at the end
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
}

log_file_handle = None


def log(message):
    """Print to console and, if enabled, write to the log file."""
    print(message)
    if log_file_handle:
        log_file_handle.write(message + "\n")
        log_file_handle.flush()


def get_protocol_name(packet):
    """Return a human-readable protocol name for a packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def process_packet(packet):
    """Callback function executed for every captured packet."""
    stats["total"] += 1

    if not packet.haslayer(IP):
        stats["other"] += 1
        return

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = get_protocol_name(packet)
    stats[proto.lower()] = stats.get(proto.lower(), 0) + 1

    line = f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {proto}"

    # Add port information for TCP/UDP
    if packet.haslayer(TCP):
        line += f" | Src Port: {packet[TCP].sport} -> Dst Port: {packet[TCP].dport}"
        flags = packet[TCP].flags
        line += f" | Flags: {flags}"
    elif packet.haslayer(UDP):
        line += f" | Src Port: {packet[UDP].sport} -> Dst Port: {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        line += f" | Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

    # Show a short preview of the raw payload, if present
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            preview = payload[:32]
            printable = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in preview
            )
            line += f" | Payload Preview: {printable}"
        except Exception:
            pass

    log(line)


def print_summary():
    log("\n" + "=" * 50)
    log("Capture Summary")
    log("=" * 50)
    log(f"Total packets captured : {stats['total']}")
    log(f"TCP packets            : {stats.get('tcp', 0)}")
    log(f"UDP packets            : {stats.get('udp', 0)}")
    log(f"ICMP packets           : {stats.get('icmp', 0)}")
    log(f"Other/Non-IP packets   : {stats.get('other', 0)}")
    log("=" * 50)


def main():
    global log_file_handle

    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Educational Use Only)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-l", "--log", help="Path to a file where captured output will also be saved")
    args = parser.parse_args()

    if args.log:
        log_file_handle = open(args.log, "a")
        log(f"\n--- New capture session started {datetime.datetime.now()} ---")

    log("[*] Starting Basic Network Sniffer")
    log("[*] For educational use on networks you own or are authorized to monitor.")
    log(f"[*] Interface : {args.interface or 'default'}")
    log(f"[*] Filter    : {args.filter or 'none'}")
    log(f"[*] Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    log("-" * 50)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        log("[!] Permission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        log("\n[*] Capture stopped by user.")
    finally:
        print_summary()
        if log_file_handle:
            log_file_handle.close()


if __name__ == "__main__":
    main()
