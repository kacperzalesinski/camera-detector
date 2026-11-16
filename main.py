#!/usr/bin/env python3
"""
main.py — Camera Detector CLI

Detects both wired (USB) and wireless (network/IP) cameras.

Usage:
    python main.py                     # scan both USB and network
    python main.py --usb-only          # only scan for wired cameras
    python main.py --network-only      # only scan for wireless cameras
    python main.py --subnet 192.168.1.0/24   # specify subnet manually
    python main.py --include-possible  # also list hosts with only generic web ports open
    python main.py --timeout 300       # network scan time limit in seconds
    python main.py --json              # output raw JSON instead of a table
"""

import argparse
import json
import sys

from detect_usb import detect_usb_cameras
from detect_network import detect_network_cameras


NMAP_HELP = (
    "  Install it with: sudo apt install nmap  (Linux)\n"
    "                   brew install nmap      (macOS)\n"
    "                   https://nmap.org/download.html (Windows)"
)


def print_table(usb_cams, net_cams):
    if usb_cams is not None:
        print("\n=== Wired (USB) Cameras ===")
        if usb_cams:
            for c in usb_cams:
                extra = f"  (also {', '.join(c['other_paths'])})" if c.get("other_paths") else ""
                print(f"  - {c['name']}  [{c['path']}]{extra}")
        else:
            print("  None found.")

    if net_cams is not None:
        print("\n=== Wireless (Network/IP) Cameras ===")
        if isinstance(net_cams, dict):
            if net_cams["error"] == "nmap_not_found":
                print("  Skipped: 'nmap' is not installed on this machine.")
                print(NMAP_HELP)
            else:
                print(f"  Scan failed ({net_cams['error']}): {net_cams['message']}")
        elif net_cams:
            for c in net_cams:
                ports = ", ".join(str(p) for p in c["open_ports"]) or "none detected"
                print(f"  - {c['ip']}  MAC: {c['mac'] or 'unknown'}  "
                      f"Vendor: {c['vendor'] or 'unknown'}  Open ports: {ports}  "
                      f"[{c['confidence']} confidence: {'; '.join(c['reasons'])}]")
        else:
            print("  None found.")
    print()


def main():
    parser = argparse.ArgumentParser(description="Detect wired and wireless cameras.")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--usb-only", action="store_true", help="Only scan for wired/USB cameras")
    scope.add_argument("--network-only", action="store_true", help="Only scan for wireless/network cameras")
    parser.add_argument("--subnet", type=str, default=None, help="Subnet to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--include-possible", action="store_true",
                        help="Also list low-confidence hosts (only generic web ports open)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Time limit in seconds for the nmap scan (default: 120)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if args.usb_only and args.subnet:
        parser.error("--subnet has no effect with --usb-only")

    usb_cams = None if args.network_only else detect_usb_cameras()
    net_cams = None if args.usb_only else detect_network_cameras(
        subnet=args.subnet, include_possible=args.include_possible, timeout=args.timeout)

    net_error = net_cams if isinstance(net_cams, dict) else None

    if args.json:
        print(json.dumps({
            "usb_cameras": usb_cams if usb_cams is not None else [],
            "network_cameras": net_cams if isinstance(net_cams, list) else [],
            "network_scan_error": net_error,
        }, indent=2))
    else:
        print_table(usb_cams, net_cams)

    # Non-zero exit if a requested scan could not run
    return 1 if net_error else 0


if __name__ == "__main__":
    sys.exit(main())
