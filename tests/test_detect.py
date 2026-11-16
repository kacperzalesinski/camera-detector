import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detect_network as dn
import detect_usb as du

PING_XML = """<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
 <address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Netgear"/></host>
<host><status state="up"/><address addr="192.168.1.24" addrtype="ipv4"/>
 <address addr="4C:11:BF:12:34:56" addrtype="mac" vendor="Zhejiang Dahua"/></host>
<host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host>
</nmaprun>"""

PORT_XML = """<nmaprun>
<host><address addr="192.168.1.1" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="80"><state state="open"/></port>
 <port protocol="tcp" portid="8080"><state state="closed"/></port></ports></host>
<host><address addr="192.168.1.24" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="554"><state state="open"/></port></ports></host>
</nmaprun>"""


class NetworkTests(unittest.TestCase):
    def test_parse_ping_sweep_skips_down_hosts(self):
        hosts = dn.parse_ping_sweep(PING_XML)
        self.assertEqual([h["ip"] for h in hosts], ["192.168.1.1", "192.168.1.24"])
        self.assertEqual(hosts[1]["mac"], "4C:11:BF:12:34:56")

    def test_parse_port_scan_only_open(self):
        self.assertEqual(dn.parse_port_scan(PORT_XML),
                         {"192.168.1.1": [80], "192.168.1.24": [554]})

    def test_router_with_http_is_low_confidence(self):
        r = dn.classify_host({"ip": "192.168.1.1", "mac": "AA:BB:CC:00:00:01",
                              "vendor": "Netgear", "open_ports": [80]})
        self.assertEqual(r["confidence"], "low")

    def test_rtsp_is_high_confidence(self):
        r = dn.classify_host({"ip": "10.0.0.5", "mac": None, "vendor": None, "open_ports": [554]})
        self.assertEqual(r["confidence"], "high")

    def test_oui_vendor_is_high_confidence(self):
        r = dn.classify_host({"ip": "10.0.0.6", "mac": "4c:11:bf:00:00:00", "vendor": None, "open_ports": []})
        self.assertEqual((r["confidence"], r["vendor"]), ("high", "Hikvision"))

    def test_onvif_responder_is_high_confidence(self):
        h = {"ip": "10.0.0.7", "mac": None, "vendor": None, "open_ports": []}
        self.assertEqual(dn.classify_host(h, {"10.0.0.7"})["confidence"], "high")

    def test_no_signal_is_not_a_camera(self):
        self.assertIsNone(dn.classify_host({"ip": "10.0.0.8", "mac": None, "vendor": "Dell", "open_ports": []}))

    def test_vendor_keyword_is_word_bounded(self):
        # "ring" must not match "Engineering"
        self.assertFalse(dn._match_vendor(None, "Acme Engineering Ltd")[1])


class UsbTests(unittest.TestCase):
    def test_parse_v4l2_groups_nodes_per_device(self):
        text = ("HD USB Camera (usb-0000:00:14.0-1):\n"
                "\t/dev/video0\n\t/dev/video1\n\n"
                "Other Cam (usb-0000:00:14.0-2):\n\t/dev/video2\n")
        devs = du.parse_v4l2_list(text)
        self.assertEqual(devs, [
            {"name": "HD USB Camera", "paths": ["/dev/video0", "/dev/video1"]},
            {"name": "Other Cam", "paths": ["/dev/video2"]},
        ])

    def test_parse_macos_json(self):
        out = du.parse_macos_profiler('{"SPCameraDataType":[{"_name":"FaceTime HD Camera"}]}')
        self.assertEqual(out[0]["name"], "FaceTime HD Camera")
        self.assertEqual(du.parse_macos_profiler("garbage"), [])

    def test_parse_windows_name_and_instance_id(self):
        out = du.parse_windows_pnp("Integrated Camera|USB\\VID_04F2&PID_B6D0\\6&1A\n\nOther|ID2\n")
        self.assertEqual([(c["name"], c["path"]) for c in out],
                         [("Integrated Camera", "USB\\VID_04F2&PID_B6D0\\6&1A"), ("Other", "ID2")])
        self.assertEqual(du.parse_windows_pnp(""), [])
        self.assertEqual(du.parse_windows_pnp("NoId")[0]["path"], "N/A")


if __name__ == "__main__":
    unittest.main()
