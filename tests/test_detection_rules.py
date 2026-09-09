"""Regression tests for the published Sigma, YARA, and Suricata rules."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import unittest

from test_pcap_tooling import (
    authentication, challenge, ethernet_ipv4_tcp, frame_bytes,
    hello, pcap, TYPE_PLAINTEXT,
)

ROOT = Path(__file__).resolve().parents[1]
HAS_YARA = importlib.util.find_spec("yara") is not None
HAS_SIGMA = importlib.util.find_spec("sigma") is not None
SURICATA = shutil.which("suricata")


def sigma_text(filename: str) -> str:
    return (ROOT / "detections" / "sigma" / filename).read_text()


class RequiredEngines(unittest.TestCase):
    def test_ci_detection_engines_are_available(self):
        if os.environ.get("PACKCLIENT_REQUIRE_DETECTION_ENGINES") == "1":
            self.assertTrue(HAS_YARA and HAS_SIGMA and SURICATA and shutil.which("tshark")
                            and importlib.util.find_spec("lz4"),
                            "CI must not silently skip detection-engine tests")


@unittest.skipUnless(HAS_SIGMA, "optional pySigma SQLite backend absent")
class SigmaRuleTests(unittest.TestCase):
    def matches(self, filename, event):
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import sqliteBackend
        rules = SigmaCollection.from_yaml((ROOT / "detections/sigma" / filename).read_text())
        queries = sqliteBackend().convert(rules)
        with sqlite3.connect(":memory:") as conn:
            conn.create_function("regexp", 2, lambda pat, value: bool(re.search(pat, value or "")))
            conn.execute("CREATE TABLE events (Image TEXT, CommandLine TEXT, ParentImage TEXT, OriginalFileName TEXT)")
            conn.execute("INSERT INTO events VALUES (?, ?, ?, ?)",
                         [event.get(k, "") for k in ("Image", "CommandLine", "ParentImage", "OriginalFileName")])
            return any(conn.execute(q.replace("<TABLE_NAME>", "events")).fetchall() for q in queries)

    def test_worker_mode_survives_renaming_but_rejects_substrings(self):
        rule = "proc_creation_win_packclient_screenshot_worker.yml"
        base = {"Image": r"C:\Temp\renamed.exe"}
        for command, expected in [
            (r'renamed.exe /scr_cap_worker \\.\pipe\synthetic', True),
            (r'renamed.exe "/scr_cap_worker" \\.\pipe\synthetic', True),
            ('renamed.exe /scr_cap_worker_extra value', False),
            ('renamed.exe --active-session', False),
            ('renamed.exe -acsi', False),
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.matches(rule, {**base, "CommandLine": command}), expected)

    def test_active_session_requires_launcher_identity(self):
        rule = "proc_creation_win_packclient_active_session.yml"
        base = {"Image": r"C:\Temp\renamed.exe"}
        self.assertFalse(self.matches(rule, {**base, "CommandLine": 'renamed.exe -acsi'}))
        self.assertFalse(self.matches(rule, {**base, "CommandLine": 'renamed.exe --active-session'}))
        self.assertTrue(self.matches(rule, {**base, "OriginalFileName": "PackClientLauncher.exe",
                                           "CommandLine": 'renamed.exe -acsi'}))
        self.assertTrue(self.matches(rule, {"Image": r"C:\Temp\PackClientLauncher.exe",
                                           "CommandLine": 'PackClientLauncher.exe --active-session'}))
        self.assertFalse(self.matches(rule, {"Image": r"C:\Temp\PackClientLauncher.exe",
                                            "CommandLine": 'PackClientLauncher.exe -acsidental'}))

    def test_bare_svchost_requires_only_the_image_path(self):
        rule = "proc_creation_win_bare_syswow64_svchost.yml"
        base = {"Image": r"C:\Windows\SysWOW64\svchost.exe", "ParentImage": r"C:\Temp\stage.exe"}
        for command, expected in [
            (r'"C:\Windows\SysWOW64\svchost.exe"', True),
            ('  C:\\WINDOWS\\SysWOW64\\svchost.exe  ', True),
            (r'"C:\Windows\SysWOW64\svchost.exe" -k netsvcs', False),
            (r'other.exe "C:\Windows\SysWOW64\svchost.exe"', False),
            (r'"C:\Windows\SysWOW64\svchost.exe', False),
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.matches(rule, {**base, "CommandLine": command}), expected)
        self.assertFalse(self.matches(rule, {**base, "CommandLine": base["Image"],
                                             "ParentImage": r"C:\Windows\System32\services.exe"}))

    def test_task_requires_creation_target_and_logon_trigger(self):
        rule = "proc_creation_win_packclient_nvsvc_task.yml"
        command = r'schtasks /Create /TN NvSvc /TR "C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe" /SC ONLOGON /RL HIGHEST /F'
        base = {"Image": r"C:\Windows\System32\schtasks.exe"}
        self.assertTrue(self.matches(rule, {**base, "CommandLine": command}))
        for changed in [command.replace('/Create', '/Query'), command.replace('/TR', '/XX'),
                        command.replace('ONLOGON', 'DAILY'), command.replace('/RL HIGHEST', ''),
                        command.replace('/TN NvSvc', '/TN OtherSvc'),
                        command.replace('NVIDIA Corporation', 'Other Corporation')]:
            self.assertFalse(self.matches(rule, {**base, "CommandLine": changed}))

    def test_attack_metadata_stays_scoped_to_each_rule(self):
        worker = sigma_text("proc_creation_win_packclient_screenshot_worker.yml")
        active = sigma_text("proc_creation_win_packclient_active_session.yml")
        bare = sigma_text("proc_creation_win_bare_syswow64_svchost.yml")
        task = sigma_text("proc_creation_win_packclient_nvsvc_task.yml")

        self.assertIn("attack.t1113", worker)
        self.assertNotIn("attack.t1134.002", worker)
        self.assertIn("attack.t1134.002", active)
        self.assertNotIn("attack.t1113", active)
        self.assertNotIn("attack.t1055", bare)
        self.assertNotIn("attack.privilege-escalation", task)
        self.assertIn("attack.t1053.005", task)


@unittest.skipUnless(HAS_YARA, "optional yara-python absent")
class YaraRuleTests(unittest.TestCase):
    @staticmethod
    def pe_header() -> bytes:
        header = bytearray(512)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", header, 0x84, 0x14C, 0, 0, 0, 0, 224, 2)
        struct.pack_into("<H", header, 0x98, 0x10B)
        return bytes(header)

    def test_marker_constellation_requires_pe_and_multiple_families(self):
        import yara
        rules = yara.compile(filepath=str(ROOT / "detections/yara/packclient_launcher.yar"))
        markers = b"\0".join([b"PLH1", b"PLC1", b"PLA1", b"1RCP", b"/scr_cap_worker",
                                b"PACK_LAUNCH_PSK", b"PackClientCore.primary.dll"])
        header = self.pe_header()
        self.assertTrue(rules.match(data=header + markers))
        self.assertFalse(rules.match(data=markers))
        self.assertFalse(rules.match(data=header + markers.replace(b"1RCP", b"xxxx")))
        self.assertFalse(rules.match(data=header + markers.replace(b"PACK_LAUNCH_PSK", b"missing")))

    def test_marker_alternative_branches_match(self):
        import yara
        rules = yara.compile(filepath=str(ROOT / "detections/yara/packclient_launcher.yar"))
        markers = b"\0".join([
            b"PLH1", b"PLC1", b"PLK1", b"1RCP", b"/scr_cap_worker",
            b"pack-launch-dev-psk", b"PackMonitorClient.PluginStore.v1",
        ])
        self.assertTrue(rules.match(data=self.pe_header() + markers))


@unittest.skipUnless(SURICATA, "optional Suricata engine absent")
class SuricataRuleTests(unittest.TestCase):
    def alert_ids(self, client_parts, server_data):
        packets = []
        client_seq, server_seq = 1000, 5000

        def send(payload, c2s, seq, ack, flags):
            raw = bytearray(ethernet_ipv4_tcp(payload, seq, client_to_server=c2s))
            struct.pack_into(">I", raw, 42, ack)
            raw[47] = flags
            packets.append((1_700_000_000, len(packets) * 1000, bytes(raw)))

        send(b"", True, client_seq, 0, 2)
        send(b"", False, server_seq, client_seq + 1, 0x12)
        client_seq += 1
        server_seq += 1
        send(b"", True, client_seq, server_seq, 0x10)
        for payload in client_parts:
            send(payload, True, client_seq, server_seq, 0x18)
            client_seq += len(payload)
            send(b"", False, server_seq, client_seq, 0x10)
        send(server_data, False, server_seq, client_seq, 0x18)
        server_seq += len(server_data)
        send(b"", True, client_seq, server_seq, 0x11)
        send(b"", False, server_seq, client_seq + 1, 0x11)
        send(b"", True, client_seq + 1, server_seq + 1, 0x10)

        with tempfile.TemporaryDirectory(prefix="packclient-rule-test-") as directory:
            path = Path(directory)
            capture = path / "synthetic.pcap"
            capture.write_bytes(pcap(packets))
            result = subprocess.run([
                SURICATA, "--runmode", "single", "-r", str(capture), "-k", "none",
                "-S", str(ROOT / "detections/suricata/packclient.rules"), "-l", directory,
                "--set", "vars.address-groups.HOME_NET=[192.0.2.0/24]",
                "--set", "vars.address-groups.EXTERNAL_NET=any",
                "--set", "stream.reassembly.depth=0",
            ], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            eve = path / "eve.json"
            self.assertTrue(eve.exists(), "Suricata must write EVE output")
            return {row["alert"]["signature_id"] for line in eve.read_text().splitlines()
                    if (row := json.loads(line)).get("event_type") == "alert"}

    def test_segmented_and_coalesced_handshake_prefixes(self):
        client = frame_bytes(TYPE_PLAINTEXT, hello()) + frame_bytes(TYPE_PLAINTEXT, authentication())
        server = frame_bytes(TYPE_PLAINTEXT, challenge())
        for parts in [[client], [client[:3], client[3:45], client[45:]]]:
            with self.subTest(lengths=list(map(len, parts))):
                self.assertEqual(self.alert_ids(parts, server), {4202601, 4202602, 4202603})

    def test_magic_without_matching_frame_or_version_does_not_alert(self):
        invalid = bytearray(frame_bytes(TYPE_PLAINTEXT, hello()))
        invalid[12] = 2
        invalid += b"PLH1 PLC1 PLA1"
        self.assertEqual(self.alert_ids([bytes(invalid)], b"ordinary synthetic bytes"), set())
