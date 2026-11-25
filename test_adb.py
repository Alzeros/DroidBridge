"""ADB helper tests. Run with python -m unittest -v test_adb."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import droidbridge


STUB_ADB = r'''
import os
import sys

args = sys.argv[1:]
log_path = os.environ.get("FAKE_ADB_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(" ".join(args) + "\n")

# Real adb calls carry a "-s <serial>" prefix; drop it before matching.
if args[:1] == ["-s"]:
    args = args[2:]

if args[:1] == ["devices"]:
    print("List of devices attached")
    print("R28M21CX3HL device product:raven model:Pixel_6_Pro device:raven transport_id:1")
    extra = os.environ.get("FAKE_ADB_EXTRA_DEVICES", "")
    if extra:
        for line in extra.splitlines():
            if line.strip():
                print(line.strip())
    print("EMU-1 offline")
elif args[:2] == ["forward", "--list"]:
    print("R28M21CX3HL tcp:5038 tcp:5038")
elif args[:2] == ["forward", "--remove"]:
    sys.exit(0)
elif args[:1] == ["forward"]:
    sys.exit(0)
else:
    sys.stderr.write("adb: unknown command\n")
    sys.exit(1)
'''


class AdbToolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.stub = self.root / "fake_adb.py"
        self.stub.write_text(STUB_ADB, encoding="utf-8")
        self.log_path = self.root / "adb.log"
        os.environ["FAKE_ADB_LOG"] = str(self.log_path)
        self.addCleanup(os.environ.pop, "FAKE_ADB_LOG", None)

    def tool(self, **kwargs):
        return droidbridge.AdbTool({"proxy": {"port": 5038}, "adb_path": ""}, **kwargs)

    def injected_tool(self, **kwargs):
        tool = self.tool(**kwargs)
        tool.resolve = lambda: [sys.executable, str(self.stub)]
        return tool

    def calls(self):
        if not self.log_path.exists():
            return []
        return self.log_path.read_text(encoding="utf-8").strip().splitlines()

    def test_devices_parsing(self):
        devices = self.injected_tool().devices()
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["serial"], "R28M21CX3HL")
        self.assertEqual(devices[0]["state"], "device")
        self.assertEqual(devices[0]["model"], "Pixel_6_Pro")
        self.assertEqual(devices[1]["serial"], "EMU-1")
        self.assertEqual(devices[1]["state"], "offline")

    def test_forwards_parsing(self):
        forwards = self.injected_tool().forwards()
        self.assertEqual(
            forwards,
            [{"serial": "R28M21CX3HL", "local": "tcp:5038", "remote": "tcp:5038"}],
        )

    def test_forward_uses_upstream_port(self):
        result = self.injected_tool().forward()
        self.assertEqual(result["local"], "tcp:5038")
        self.assertEqual(result["remote"], "tcp:5038")
        self.assertIn("-s R28M21CX3HL forward tcp:5038 tcp:5038", self.calls())

    def test_unforward_uses_upstream_port(self):
        result = self.injected_tool().unforward()
        self.assertEqual(result["local"], "tcp:5038")
        self.assertIn("-s R28M21CX3HL forward --remove tcp:5038", self.calls())

    def test_online_device_skips_offline(self):
        device = self.injected_tool().online_device()
        self.assertEqual(device["serial"], "R28M21CX3HL")

    def test_configured_path_wins_over_path(self):
        cfg = {"proxy": {"port": 5038}, "adb_path": str(self.stub)}
        tool = droidbridge.AdbTool(cfg)
        with patch.object(droidbridge.shutil, "which", return_value=r"C:\fake\adb.exe"):
            self.assertEqual(tool.resolve(), [str(self.stub)])

    def test_resolve_falls_back_to_path(self):
        tool = self.tool()
        with patch.object(droidbridge.shutil, "which", return_value=r"C:\fake\adb.exe"):
            self.assertEqual(tool.resolve(), [r"C:\fake\adb.exe"])

    def test_resolve_returns_none_without_adb(self):
        tool = self.tool()
        with patch.object(droidbridge.shutil, "which", return_value=None):
            self.assertIsNone(tool.resolve())

    def test_state_reports_missing_adb(self):
        tool = self.tool()
        with patch.object(droidbridge.shutil, "which", return_value=None):
            state = tool.state()
        self.assertFalse(state["adb_found"])
        self.assertIn("未找到 adb", state["error"])
        self.assertEqual(state["upstream_port"], 5038)

    def test_failed_command_reports_stderr(self):
        tool = self.injected_tool()
        code, _out, err = tool.run(["--bogus"])
        self.assertNotEqual(code, 0)
        self.assertIn("unknown command", err)

    def test_devices_raises_on_failure(self):
        tool = self.injected_tool()
        tool.run = lambda args: (1, "", "adb: no devices")
        with self.assertRaises(droidbridge.AdbError) as ctx:
            tool.devices()
        self.assertIn("no devices", str(ctx.exception))

    def test_timeout_is_reported(self):
        slow = self.root / "slow_adb.py"
        slow.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        tool = self.injected_tool(timeout=0.5)
        tool.resolve = lambda: [sys.executable, str(slow)]
        with self.assertRaises(droidbridge.AdbError) as ctx:
            tool.run(["devices"])
        self.assertIn("超时", str(ctx.exception))

    def test_multi_device_selection_and_fallback(self):
        os.environ["FAKE_ADB_EXTRA_DEVICES"] = "SECOND999 device model:Pixel_8"
        self.addCleanup(os.environ.pop, "FAKE_ADB_EXTRA_DEVICES", None)

        tool = self.injected_tool()
        self.assertEqual(tool.online_device(serial="SECOND999")["serial"], "SECOND999")
        res = tool.forward(serial="SECOND999")
        self.assertEqual(res["serial"], "SECOND999")
        self.assertIn("-s SECOND999 forward tcp:5038 tcp:5038", self.calls())

        unfwd = tool.unforward(serial="SECOND999")
        self.assertEqual(unfwd["serial"], "SECOND999")
        self.assertIn("-s SECOND999 forward --remove tcp:5038", self.calls())

        with self.assertRaises(droidbridge.AdbError):
            tool.online_device(serial="MISSING")

        pref_tool = droidbridge.AdbTool({"proxy": {"port": 5038}, "adb_path": "", "adb_serial": "SECOND999"})
        pref_tool.resolve = lambda: [sys.executable, str(self.stub)]
        self.assertEqual(pref_tool.online_device()["serial"], "SECOND999")
        self.assertEqual(pref_tool.state()["selected_serial"], "SECOND999")

        fallback_tool = droidbridge.AdbTool({"proxy": {"port": 5038}, "adb_path": "", "adb_serial": "GONE"})
        fallback_tool.resolve = lambda: [sys.executable, str(self.stub)]
        self.assertEqual(fallback_tool.online_device()["serial"], "R28M21CX3HL")


if __name__ == "__main__":
    unittest.main()
