"""
detect_network.py
Detects wireless / IP cameras on the local network.

Techniques used:
  1. ARP/ping sweep of the local subnet (one nmap call, if installed)
  2. One batched port check on common camera ports (554 RTSP, 80/8080 HTTP, 8000)
  3. MAC OUI (vendor prefix) and nmap vendor-string matching
  4. ONVIF WS-Discovery (UDP multicast probe, standard library only)

Hosts are classified by confidence:
  high - camera-vendor MAC, RTSP port (554) open, or answered an ONVIF probe
  low  - only generic web ports open (routers, NAS, printers also look like this)

This is a best-effort LAN scanner. It only inspects devices on your own
network and does not attempt to access or authenticate to any camera.
"""

import ipaddress
import re
import shutil
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

# Common ports used by IP cameras
CAMERA_PORTS = [80, 554, 8000, 8080, 8443]
RTSP_PORT = 554

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

# Vendor names (as printed by nmap's own OUI database) that indicate a camera
CAMERA_VENDOR_KEYWORDS = (
    "hikvision", "dahua", "foscam", "axis communications", "reolink",
    "amcrest", "wyze", "ring", "arlo", "ubiquiti", "vivotek", "hanwha",
    "uniview", "lorex", "annke", "eufy", "nest", "blink",
)

ONVIF_MULTICAST = ("239.255.255.250", 3702)


class ScanError(Exception):
    """Raised for scan failures; `code` is a short machine-readable string."""

    def __init__(self, code, message=""):
        super().__init__(message or code)
        self.code = code


def _nmap_available():
    return shutil.which("nmap") is not None


# --------------------------------------------------------------------------
# nmap parsing (XML output is stable; text output is not)
# --------------------------------------------------------------------------

def parse_ping_sweep(xml_text):
    """Parse `nmap -sn -oX -` output into [{ip, mac, vendor, open_ports}]."""
    hosts = []
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        entry = {"ip": None, "mac": None, "vendor": None, "open_ports": []}
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                entry["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                entry["mac"] = addr.get("addr")
                entry["vendor"] = addr.get("vendor")
        if entry["ip"]:
            hosts.append(entry)
    return hosts


def parse_port_scan(xml_text):
    """Parse `nmap -p ... --open -oX -` output into {ip: [open ports]}."""
    result = {}
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        ip = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
        if not ip:
            continue
        ports = []
        for p in h.findall("./ports/port"):
            state = p.find("state")
            if p.get("protocol") == "tcp" and state is not None and state.get("state") == "open":
                ports.append(int(p.get("portid")))
        result[ip] = sorted(ports)
    return result


def _run_nmap(args, timeout):
    try:
        proc = subprocess.run(["nmap"] + args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError("scan_timeout", f"nmap did not finish within {timeout}s; "
                        "try a smaller --subnet or a larger --timeout")
    except OSError as e:
        raise ScanError("nmap_failed", str(e))
    if proc.returncode != 0 or not proc.stdout.strip():
        raise ScanError("nmap_failed", (proc.stderr or "nmap returned no output").strip())
    return proc.stdout


def scan_subnet(subnet=None, timeout=120):
    """
    Ping-sweep `subnet` (e.g. '192.168.1.0/24'; guessed if None), then port-scan
    all live hosts in a single nmap invocation. Raises ScanError on failure.
    Returns [{ip, mac, vendor, open_ports}].
    """
    if not _nmap_available():
        raise ScanError("nmap_not_found")

    if subnet is None:
        subnet = _guess_subnet()
        if subnet is None:
            raise ScanError("no_subnet", "could not determine local subnet; pass --subnet")
    else:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            raise ScanError("invalid_subnet", f"{subnet!r} is not a valid CIDR subnet, e.g. 192.168.1.0/24")

    deadline = time.monotonic() + timeout
    hosts = parse_ping_sweep(_run_nmap(["-sn", "-oX", "-", subnet], timeout))
    if not hosts:
        return []

    remaining = max(5, int(deadline - time.monotonic()))
    port_str = ",".join(str(p) for p in CAMERA_PORTS)
    ports = parse_port_scan(
        _run_nmap(["-p", port_str, "--open", "-oX", "-"] + [h["ip"] for h in hosts], remaining)
    )
    for h in hosts:
        h["open_ports"] = ports.get(h["ip"], [])
    return hosts


# --------------------------------------------------------------------------
# ONVIF WS-Discovery
# --------------------------------------------------------------------------

_ONVIF_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header>
<w:MessageID>uuid:{msg_id}</w:MessageID>
<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
</e:Header>
<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>
</e:Envelope>"""


def onvif_discover(wait=3.0):
    """
    Send a WS-Discovery probe and return the set of IPs that answer as ONVIF
    NetworkVideoTransmitters. Best-effort: returns an empty set on any error
    (multicast is often blocked in containers / on isolated Wi-Fi).
    """
    found = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        sock.sendto(_ONVIF_PROBE.format(msg_id=uuid.uuid4()).encode(), ONVIF_MULTICAST)
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if b"NetworkVideoTransmitter" in data or b"ProbeMatch" in data:
                found.add(addr[0])
    except OSError:
        pass
    finally:
        if sock is not None:
            sock.close()
    return found


# --------------------------------------------------------------------------

def _guess_subnet():
    """Best-effort guess of the local /24 subnet based on the machine's own IP."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # UDP connect: no packets are sent
        local_ip = s.getsockname()[0]
        parts = local_ip.split(".")
        return f"{'.'.join(parts[:3])}.0/24"
    except OSError:
        return None
    finally:
        if s is not None:
            s.close()


def _match_vendor(mac, nmap_vendor):
    """Return (vendor_name, is_camera_vendor)."""
    if mac:
        known = CAMERA_OUI_PREFIXES.get(mac.upper()[0:8])
        if known:
            return known, True
    if nmap_vendor:
        low = nmap_vendor.lower()
        if any(re.search(rf"\b{re.escape(k)}\b", low) for k in CAMERA_VENDOR_KEYWORDS):
            return nmap_vendor, True
    return nmap_vendor, False


def classify_host(host, onvif_ips=frozenset()):
    """Return a result dict with a 'confidence' of 'high'/'low', or None if not camera-like."""
    camera_ports = [p for p in host["open_ports"] if p in CAMERA_PORTS]
    vendor, vendor_is_camera = _match_vendor(host.get("mac"), host.get("vendor"))
    is_onvif = host["ip"] in onvif_ips

    reasons = []
    if vendor_is_camera:
        reasons.append("camera vendor MAC")
    if RTSP_PORT in camera_ports:
        reasons.append("RTSP port open")
    if is_onvif:
        reasons.append("ONVIF response")

    if reasons:
        confidence = "high"
    elif camera_ports:
        confidence = "low"
        reasons.append("generic web port open only")
    else:
        return None

    return {
        "ip": host["ip"],
        "mac": host.get("mac"),
        "vendor": vendor,
        "open_ports": camera_ports,
        "type": "Network/Wireless (IP camera)",
        "confidence": confidence,
        "reasons": reasons,
    }


def detect_network_cameras(subnet=None, include_possible=False, timeout=120, onvif=True):
    """
    Detect likely wireless/IP cameras on the LAN.

    Returns a list of dicts: {ip, mac, vendor, open_ports, type, confidence, reasons}.
    Low-confidence hosts (only generic web ports open) are omitted unless
    include_possible=True. On failure returns {"error": <code>, "message": <text>}.
    """
    try:
        hosts = scan_subnet(subnet, timeout=timeout)
    except ScanError as e:
        return {"error": e.code, "message": str(e)}

    onvif_ips = onvif_discover() if onvif else set()
    # ONVIF responders that nmap didn't list (e.g. ICMP blocked) are still cameras
    known_ips = {h["ip"] for h in hosts}
    for ip in sorted(onvif_ips - known_ips):
        hosts.append({"ip": ip, "mac": None, "vendor": None, "open_ports": []})

    results = []
    for host in hosts:
        r = classify_host(host, onvif_ips)
        if r and (r["confidence"] == "high" or include_possible):
            results.append(r)
    return results


if __name__ == "__main__":
    result = detect_network_cameras()
    if isinstance(result, dict):
        print(f"Network scan failed ({result['error']}): {result['message']}")
    else:
        for cam in result:
            print(cam)
