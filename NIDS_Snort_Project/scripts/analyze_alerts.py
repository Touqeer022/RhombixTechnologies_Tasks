#!/usr/bin/env python3
"""
analyze_alerts.py - summarise a Snort 2.x "alert fast" log.
Usage:  python3 analyze_alerts.py /var/log/snort/alert
Output: totals per rule, per source IP, per hour, plus a CSV file.
"""
import re
import sys
import csv
from collections import Counter

# Example line:
# 10/26-09:15:02.123456  [**] [1:1000002:1] LAB Possible Nmap SYN Port Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.10:44321 -> 192.168.56.20:80
PATTERN = re.compile(
    r"^(?P<ts>\d\d/\d\d-\d\d:\d\d:\d\d\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+\[\*\*\]\s+(?:\[Classification: (?P<cls>[^\]]+)\]\s+)?"
    r"(?:\[Priority: (?P<prio>\d+)\]\s+)?\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src>[\d\.]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dst>[\d\.]+)(?::(?P<dport>\d+))?"
)


def main(path):
    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = PATTERN.match(line.strip())
            if m:
                rows.append(m.groupdict())

    if not rows:
        print("No alerts parsed. Check the file path and that Snort uses 'alert_fast' output.")
        return

    print(f"\nTotal alerts parsed: {len(rows)}\n")

    print("== Alerts per rule ==")
    for (sid, msg), n in Counter((r["sid"], r["msg"]) for r in rows).most_common():
        print(f"  {n:6d}  sid:{sid}  {msg}")

    print("\n== Top source IPs ==")
    for ip, n in Counter(r["src"] for r in rows).most_common(10):
        print(f"  {n:6d}  {ip}")

    print("\n== Top targeted ports ==")
    for port, n in Counter(r["dport"] or "n/a" for r in rows).most_common(10):
        print(f"  {n:6d}  {port}")

    print("\n== Protocols ==")
    for proto, n in Counter(r["proto"] for r in rows).most_common():
        print(f"  {n:6d}  {proto}")

    print("\n== Alerts per hour ==")
    for hour, n in sorted(Counter(r["ts"][:8] for r in rows).items()):
        print(f"  {hour}:00  {n}")

    out = "alerts_parsed.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nCSV saved: {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/var/log/snort/alert")
