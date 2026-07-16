# Camera Detector

A cross-platform command-line tool that detects **both wired (USB) and
wireless (network/IP) cameras** connected to or reachable from your
machine.

## What it does

- **Wired cameras**: Detected using OS-native tools
  - Linux → `v4l2-ctl --list-devices` (falls back to `lsusb`)
  - macOS → `system_profiler SPCameraDataType`
  - Windows → `Get-PnpDevice -Class Camera,Image` (PowerShell)
- **Wireless / IP cameras**: Detected by scanning your local network
  - Ping-sweeps your subnet using `nmap`
  - Checks common camera ports (80, 554 RTSP, 8000, 8080, 8443)
  - Cross-references device MAC address prefixes against known camera
    vendors (Hikvision, Dahua, Foscam, TP-Link/Tapo, Wyze, Ring, etc.)

This only scans devices already on your own network — it does not try
to log into, stream from, or exploit any camera it finds.

## Requirements

- Python 3.8+
- `nmap` installed and on your PATH (for wireless detection)
  - Linux: `sudo apt install nmap`
  - macOS: `brew install nmap`
  - Windows: https://nmap.org/download.html
- (Optional, Linux) `v4l-utils` for cleaner USB device names:
  `sudo apt install v4l-utils`

No pip packages are required — everything uses the Python standard
library.

## Usage

Clone the repo and run it from the terminal:

```bash
git clone <your-repo-url>
cd camera-detector
python3 main.py
```

### Options

```bash
python3 main.py --usb-only            # only scan for wired cameras
python3 main.py --network-only        # only scan for wireless cameras
python3 main.py --subnet 192.168.1.0/24   # manually specify subnet
python3 main.py --json                # print results as JSON
```

### Example output

```
=== Wired (USB) Cameras ===
  - HD USB Camera  [/dev/video0]

=== Wireless (Network/IP) Cameras ===
  - 192.168.1.24  MAC: 4C:11:BF:xx:xx:xx  Vendor: Hikvision  Open ports: 80, 554
```

## Notes / limitations

- Network scanning requires your machine to be on the same subnet as
  the camera(s) and may need to be run with elevated privileges
  (`sudo python3 main.py`) for full nmap functionality (e.g. MAC
  address resolution).
- Some routers isolate wireless clients from each other (client/AP
  isolation), which can hide cameras even though they're on the same
  Wi-Fi network — check your router settings if a known camera isn't
  showing up.
- The vendor MAC list in `detect_network.py` is a small starter set —
  feel free to extend `CAMERA_OUI_PREFIXES` with more vendors.

## Project structure

```
camera-detector/
├── detect_usb.py       # wired camera detection (USB/UVC devices)
├── detect_network.py   # wireless/IP camera detection (LAN scan)
├── main.py             # CLI entry point
├── requirements.txt
└── README.md
```
