# Camera Detector

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

A cross-platform command-line tool that detects **both wired (USB) and wireless (network/IP) cameras** connected to, or reachable from, your machine.

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example output](#example-output)
- [Limitations](#limitations)
- [Project structure](#project-structure)

## How it works

**Wired cameras** are detected using OS-native tools:

| OS | Method |
|---|---|
| Linux | `v4l2-ctl --list-devices` (falls back to `lsusb`) |
| macOS | `system_profiler SPCameraDataType` |
| Windows | `Get-PnpDevice -Class Camera,Image` (PowerShell) |

**Wireless / IP cameras** are detected by scanning your local network:

- Ping-sweeps your subnet using `nmap`
- Checks common camera ports (`80`, `554` RTSP, `8000`, `8080`, `8443`)
- Cross-references device MAC address prefixes against known camera vendors (Hikvision, Dahua, Foscam, TP-Link/Tapo, Wyze, Ring, etc.)

> This tool only inspects devices already on your own network — it never attempts to log into, stream from, or exploit any camera it finds.

## Requirements

- Python 3.8+
- `nmap` on your `PATH` (required for wireless detection)
  - Linux: `sudo apt install nmap`
  - macOS: `brew install nmap`
  - Windows: [nmap.org/download.html](https://nmap.org/download.html)
- *(Optional, Linux)* `v4l-utils` for cleaner USB device names: `sudo apt install v4l-utils`

No pip packages are required — everything uses the Python standard library.

## Installation

```bash
git clone https://github.com/ranjansinghx/camera-detector.git
cd camera-detector
```

## Usage

```bash
python3 main.py
```

### Options

| Flag | Description |
|---|---|
| `--usb-only` | Only scan for wired/USB cameras |
| `--network-only` | Only scan for wireless/network cameras |
| `--subnet 192.168.1.0/24` | Manually specify the subnet to scan |
| `--json` | Print results as JSON instead of a table |

## Example output

```
=== Wired (USB) Cameras ===
  - HD USB Camera  [/dev/video0]

=== Wireless (Network/IP) Cameras ===
  - 192.168.1.24  MAC: 4C:11:BF:xx:xx:xx  Vendor: Hikvision  Open ports: 80, 554
```

## Limitations

- Network scanning requires your machine to be on the same subnet as the camera(s), and may need elevated privileges (`sudo python3 main.py`) for full nmap functionality such as MAC address resolution.
- Some routers isolate wireless clients from one another (client/AP isolation), which can hide cameras even on the same Wi-Fi network — check your router settings if a known camera isn't showing up.
- The vendor MAC list in `detect_network.py` is a small starter set. Feel free to extend `CAMERA_OUI_PREFIXES` with more vendors.

## Project structure

```
camera-detector/
├── detect_usb.py       # wired camera detection (USB/UVC devices)
├── detect_network.py   # wireless/IP camera detection (LAN scan)
├── main.py             # CLI entry point
├── requirements.txt
└── README.md
```
