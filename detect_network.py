"""
detect_network.py
Detects wireless / IP cameras on the local network.

Techniques used:
  1. ARP/ping sweep of the local subnet (via nmap, if installed)
  2. Port check on common camera ports (554 RTSP, 80/8080 HTTP, 8000)
  3. MAC OUI (vendor prefix) matching against known camera manufacturers
  4. Optional ONVIF WS-Discovery (if 'onvif' / 'wsdiscovery' extras installed)

This is a best-effort LAN scanner. It only inspects devices on your own
network and does not attempt to access or authenticate to any camera.
"""

import re
import shutil
import socket
import subprocess

# Common ports used by IP cameras
CAMERA_PORTS = [80, 554, 8000, 8080, 8443]

# A small set of known camera-vendor MAC OUI prefixes (first 3 bytes)
CAMERA_OUI_PREFIXES = {
    "00:12:2E": "Hikvision",
    "4C:11:BF": "Hikvision",
    "BC:AD:28": "Hikvision",
    "00:0F:7C": "Dahua",
    "3C:EF:8C": "Dahua",
    "9C:8E:CD": "Dahua",
    "00:62:6E": "Foscam",
    "84:1B:5E": "Foscam",
    "2C:AA:8E": "TP-Link (Tapo/Kasa cams)",
    "50:C7:BF": "TP-Link (Tapo/Kasa cams)",
    "68:FF:7B": "Wyze",
    "2C:AA:A2": "Wyze",
    "AC:CF:23": "Ring",
    "F0:B4:29": "Ring",
}


def _nmap_available():
    return shutil.which("nmap") is not None


def scan_subnet(subnet=None):
    """
    Run an nmap ping-sweep + port scan over the given subnet
    (e.g. '192.168.1.0/24'). If subnet is None, tries to guess it.
    Returns a list of dicts: {ip, mac, vendor, open_ports}
    """
    if not _nmap_available():
        return None  # signal caller that nmap isn't installed

    if subnet is None:
        subnet = _guess_subnet()
        if subnet is None:
            return []

    port_str = ",".join(str(p) for p in CAMERA_PORTS)
    cmd = ["nmap", "-sn", subnet]  # ping sweep first to find live hosts
    try:
        live_out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return []

    hosts = []
    current = {}
    for line in live_out.splitlines():
        ip_match = re.search(r"Nmap scan report for (?:.*\()?([\d.]+)\)?", line)
        mac_match = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+)\)", line, re.IGNORECASE)
        if ip_match:
            if current:
                hosts.append(current)
            current = {"ip": ip_match.group(1), "mac": None, "vendor": None, "open_ports": []}
        elif mac_match and current:
            current["mac"] = mac_match.group(1)
            current["vendor"] = mac_match.group(2)
    if current:
        hosts.append(current)

    # Now check camera-relevant ports on each live host
    for host in hosts:
        cmd = ["nmap", "-p", port_str, "--open", host["ip"]]
        try:
            port_out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        except Exception:
            continue
        for line in port_out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open", line.strip())
            if m:
                host["open_ports"].append(int(m.group(1)))

    return hosts


def _guess_subnet():
    """Best-effort guess of the local /24 subnet based on the machine's own IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{'.'.join(parts[:3])}.0/24"
    except Exception:
        return None


def _match_vendor_by_oui(mac):
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return CAMERA_OUI_PREFIXES.get(prefix)


def detect_network_cameras(subnet=None):
    """
    Detect likely wireless/IP cameras on the LAN.
    Returns a list of dicts: {ip, mac, vendor, open_ports, likely_camera, type}
    """
    hosts = scan_subnet(subnet)

    if hosts is None:
        # nmap not installed
        return {"error": "nmap_not_found"}

    results = []
    for host in hosts:
        camera_ports_open = [p for p in host["open_ports"] if p in CAMERA_PORTS]
        oui_vendor = _match_vendor_by_oui(host.get("mac"))

        likely = bool(camera_ports_open) or oui_vendor is not None
        if likely:
            results.append({
                "ip": host["ip"],
                "mac": host.get("mac"),
                "vendor": oui_vendor or host.get("vendor"),
                "open_ports": camera_ports_open,
                "type": "Network/Wireless (IP camera)",
            })

    return results


if __name__ == "__main__":
    result = detect_network_cameras()
    if isinstance(result, dict) and result.get("error") == "nmap_not_found":
        print("nmap is not installed. Install it to enable network camera scanning.")
    else:
        for cam in result:
            print(cam)
