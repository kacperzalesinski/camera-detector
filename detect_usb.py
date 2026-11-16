"""
detect_usb.py
Detects wired (USB) cameras connected to the local machine.
Works cross-platform: Linux, macOS, Windows.
"""

import platform
import subprocess
import re


def _run(cmd, timeout=10):
    """Run a shell command and return stdout as text, or '' on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str)
        )
        return result.stdout
    except Exception:
        return ""


def detect_linux():
    cameras = []

    # Preferred: v4l2-ctl gives clean device names + paths
    out = _run(["v4l2-ctl", "--list-devices"])
    if out:
        current_name = None
        for line in out.splitlines():
            if line and not line.startswith("\t") and not line.startswith(" "):
                current_name = line.split("(")[0].strip()
            elif line.strip().startswith("/dev/video"):
                cameras.append({
                    "name": current_name or "Unknown camera",
                    "path": line.strip(),
                    "type": "USB (wired)",
                })

    # Fallback / supplement: lsusb for identifying camera-class USB devices
    if not cameras:
        out = _run(["lsusb"])
        for line in out.splitlines():
            if re.search(r"camera|webcam|video", line, re.IGNORECASE):
                cameras.append({
                    "name": line.strip(),
                    "path": "N/A (no /dev/video node found)",
                    "type": "USB (wired)",
                })

    return cameras


def detect_macos():
    cameras = []
    out = _run(["system_profiler", "SPCameraDataType"])
    if out:
        name = None
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if line.endswith(":") and not line.startswith("Camera"):
                name = line.rstrip(":")
            elif line and name and "Model ID" not in line and ":" not in line:
                continue
        # system_profiler output is a nested plist-like text; simplest robust
        # approach is to grab top-level device names (lines ending in ':')
        for raw_line in out.splitlines():
            stripped = raw_line.strip()
            if stripped.endswith(":") and raw_line.startswith("    ") and not raw_line.startswith("      "):
                cameras.append({
                    "name": stripped.rstrip(":"),
                    "path": "N/A (macOS abstracts device paths)",
                    "type": "USB/Built-in (wired)",
                })
    return cameras


def detect_windows():
    cameras = []
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
    out = _run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=60)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        name, _, instance_id = line.partition("|")
        cameras.append({
            "name": name.strip() or "Unknown camera",
            "path": instance_id.strip() or "N/A",
            "type": "USB (wired)",
        })
    return cameras


def detect_usb_cameras():
    """Detect wired/USB cameras on the current OS. Returns a list of dicts."""
    system = platform.system()
    if system == "Linux":
        return detect_linux()
    elif system == "Darwin":
        return detect_macos()
    elif system == "Windows":
        return detect_windows()
    else:
        return []


if __name__ == "__main__":
    for cam in detect_usb_cameras():
        print(cam)
