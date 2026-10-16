#!/usr/bin/env python3
"""
DeadByte SOC Toolkit - log_triage.py

A defensive log triage helper:
- Reads plaintext logs
- Counts IP addresses
- Flags repeated failed-login patterns
- Extracts SHA256-like values
- Writes a JSON summary

Designed for blue-team / lab use.
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
FAIL_WORDS = ("failed password", "authentication failure", "login failed", "invalid user")

def valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except Exception:
        return False

def triage(text: str):
    ips = [ip for ip in IP_RE.findall(text) if valid_ip(ip)]
    hashes = SHA256_RE.findall(text)

    failed_lines = []
    for line in text.splitlines():
        low = line.lower()
        if any(p in low for p in FAIL_WORDS):
            failed_lines.append(line)

    failed_ips = []
    for line in failed_lines:
        failed_ips.extend(ip for ip in IP_RE.findall(line) if valid_ip(ip))

    return {
        "top_ips": Counter(ips).most_common(20),
        "failed_auth_count": len(failed_lines),
        "top_failed_auth_ips": Counter(failed_ips).most_common(20),
        "sha256_values": sorted(set(hashes)),
        "sample_failed_auth_lines": failed_lines[:20],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("-o", "--output", default="triage_report.json")
    args = ap.parse_args()

    path = Path(args.logfile)
    text = path.read_text(errors="replace")
    report = triage(text)

    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSaved: {args.output}")

if __name__ == "__main__":
    main()
