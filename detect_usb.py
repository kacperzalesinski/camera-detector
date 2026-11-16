"""
detect_usb.py
Detects wired (USB / built-in) cameras connected to the local machine.
Works cross-platform: Linux, macOS, Windows.
"""

import glob
import json
import os
import platform
import re
import subprocess


def _run(cmd, timeout=10):
    """Run a command (list) and return stdout as text, or '' on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------

def _is_capture_node(dev_path):
    """
    A single physical UVC camera usually exposes several /dev/videoN nodes
    (e.g. video0 = capture, video1 = metadata). Per the V4L2 UVC driver the
    capture node has sysfs 'index' 0. If sysfs is unavailable, assume capture.
    """
    node = os.path.basename(dev_path)
    index_file = f"/sys/class/video4linux/{node}/index"
    try:
        with open(index_file) as f:
            return f.read().strip() == "0"
    except OSError:
        return True


def parse_v4l2_list(text):
    """
    Parse `v4l2-ctl --list-devices` output into
    [{"name": str, "paths": [str, ...]}], one entry per physical device.
    """
    devices = []
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            # Header line: "HD USB Camera (usb-0000:00:14.0-1):"
            current = {"name": re.sub(r"\s*\(.*\):?\s*$", "", line).strip().rstrip(":"),
                       "paths": []}
            devices.append(current)
        elif current is not None and line.strip().startswith("/dev/video"):
            current["paths"].append(line.strip())
    return devices


def _linux_from_v4l2():
    cameras = []
    for dev in parse_v4l2_list(_run(["v4l2-ctl", "--list-devices"])):
        capture = [p for p in dev["paths"] if _is_capture_node(p)]
        if not capture:
            continue  # only metadata/output nodes -> not a usable camera
        cameras.append({
            "name": dev["name"] or "Unknown camera",
            "path": capture[0],
            "other_paths": [p for p in dev["paths"] if p != capture[0]],
            "type": "USB (wired)",
        })
    return cameras


def _linux_from_sysfs():
    """Fallback when v4l2-ctl is missing: read names straight from sysfs."""
    cameras = []
    for node_dir in sorted(glob.glob("/sys/class/video4linux/video*")):
        node = os.path.basename(node_dir)
        dev_path = f"/dev/{node}"
        if not _is_capture_node(dev_path):
            continue
        try:
            with open(os.path.join(node_dir, "name")) as f:
                name = f.read().strip()
        except OSError:
            name = "Unknown camera"
        cameras.append({"name": name, "path": dev_path, "other_paths": [],
                        "type": "USB (wired)"})
    return cameras


def _linux_from_lsusb():
    cameras = []
    for line in _run(["lsusb"]).splitlines():
        if re.search(r"camera|webcam|video", line, re.IGNORECASE):
            cameras.append({
                "name": line.strip(),
                "path": "N/A (no /dev/video node found)",
                "other_paths": [],
                "type": "USB (wired)",
            })
    return cameras


def detect_linux():
    return _linux_from_v4l2() or _linux_from_sysfs() or _linux_from_lsusb()


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------

def parse_macos_profiler(json_text):
    """Parse `system_profiler SPCameraDataType -json` output."""
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        return []
    return [
        {
            "name": item.get("_name", "Unknown camera"),
            "path": "N/A (macOS abstracts device paths)",
            "other_paths": [],
            "type": "USB/Built-in (wired)",
        }
        for item in data.get("SPCameraDataType", [])
    ]


def detect_macos():
    return parse_macos_profiler(_run(["system_profiler", "SPCameraDataType", "-json"]))


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

def parse_windows_pnp(text):
    """Parse 'FriendlyName|InstanceId' lines, one device per line."""
    cameras = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        name, _, instance_id = line.partition("|")
        cameras.append({
            "name": name.strip() or "Unknown camera",
            "path": instance_id.strip() or "N/A",
            "other_paths": [],
            "type": "USB (wired)",
        })
    return cameras


def detect_windows():
    # Query each class separately: Get-PnpDevice throws a terminating error if
    # *any* class in a -Class list has no devices (e.g. no "Image" devices),
    # which previously made the whole query return nothing.
    ps_cmd = (
        "foreach ($c in 'Camera','Image') { "
        "Get-PnpDevice -Class $c -PresentOnly -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.FriendlyName + '|' + $_.InstanceId } }"
    )
    # PowerShell + Get-PnpDevice can take ~10s on a cold start, so allow more
    # than the default 10s timeout (which caused intermittent empty results).
    return parse_windows_pnp(_run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=60))


# --------------------------------------------------------------------------

def detect_usb_cameras():
    """Detect wired/USB cameras on the current OS. Returns a list of dicts."""
    system = platform.system()
    if system == "Linux":
        return detect_linux()
    if system == "Darwin":
        return detect_macos()
    if system == "Windows":
        return detect_windows()
    return []


if __name__ == "__main__":
    for cam in detect_usb_cameras():
        print(cam)
