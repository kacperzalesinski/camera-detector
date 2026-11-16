#!/usr/bin/env python3
"""
main.py — Camera Detector CLI

Detects both wired (USB) and wireless (network/IP) cameras.

Usage:
    python main.py                     # scan both USB and network
    python main.py --usb-only          # only scan for wired cameras
    python main.py --network-only      # only scan for wireless cameras
    python main.py --subnet 192.168.1.0/24   # specify subnet manually
    python main.py --json              # output raw JSON instead of a table
"""

import argparse
import json
import sys

from detect_usb import detect_usb_cameras
from detect_network import detect_network_cameras


def print_table(usb_cams, net_cams, show_usb=True, show_net=True):
    if show_usb:
        print("\n=== Wired (USB) Cameras ===")
        if usb_cams:
            for c in usb_cams:
                print(f"  - {c['name']}  [{c['path']}]")
        else:
            print("  None found.")

    if show_net:
        print("\n=== Wireless (Network/IP) Cameras ===")
        if isinstance(net_cams, dict) and net_cams.get("error") == "nmap_not_found":
            print("  Skipped: 'nmap' is not installed on this machine.")
            print("  Install it with: sudo apt install nmap  (Linux)")
            print("                   brew install nmap      (macOS)")
            print("                   https://nmap.org/download.html (Windows)")
        elif net_cams:
            for c in net_cams:
                ports = ", ".join(str(p) for p in c["open_ports"]) or "none detected"
                print(f"  - {c['ip']}  MAC: {c['mac'] or 'unknown'}  "
                      f"Vendor: {c['vendor'] or 'unknown'}  Open ports: {ports}")
        else:
            print("  None found.")
    print()


def main():
    parser = argparse.ArgumentParser(description="Detect wired and wireless cameras.")
    parser.add_argument("--usb-only", action="store_true", help="Only scan for wired/USB cameras")
    parser.add_argument("--network-only", action="store_true", help="Only scan for wireless/network cameras")
    parser.add_argument("--subnet", type=str, default=None, help="Subnet to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    usb_cams = []
    net_cams = []

    if not args.network_only:
        usb_cams = detect_usb_cameras()

    if not args.usb_only:
        net_cams = detect_network_cameras(subnet=args.subnet)

    if args.json:
        output = {
            "usb_cameras": usb_cams,
            "network_cameras": net_cams if not (isinstance(net_cams, dict)) else [],
            "network_scan_error": net_cams.get("error") if isinstance(net_cams, dict) else None,
        }
        print(json.dumps(output, indent=2))
    else:
        print_table(usb_cams, net_cams,
                    show_usb=not args.network_only,
                    show_net=not args.usb_only)


if __name__ == "__main__":
    main()
