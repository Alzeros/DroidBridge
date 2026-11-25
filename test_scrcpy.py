import base64
import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

import scrcpy_bridge


def _mask_ws_frame(opcode: int, payload: bytes, fin: bool = True, mask_key: bytes = b"\x12\x34\x56\x78", masked: bool = True) -> bytes:
    first = (0x80 if fin else 0x00) | (opcode & 0x0F)
    length = len(payload)
    mask_bit = 0x80 if masked else 0x00
    if length < 126:
        header = struct.pack("!BB", first, mask_bit | length)
    elif length < 65536:
        header = struct.pack("!BBH", first, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, length)
    if not masked:
        return header + payload
    masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return header + mask_key + masked_payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        data = sock.recv(n - len(chunks))
        if not data:
            raise EOFError("unexpected EOF")
        chunks.extend(data)
    return bytes(chunks)


def _read_server_ws_frame(sock: socket.socket) -> tuple[bool, int, bytes]:
    b1, b2 = _recv_exact(sock, 2)
    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    mask_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


class ScrcpyBinaryAndProtocolTests(unittest.TestCase):
    def test_bundled_scrcpy_server_verifies_sha256(self):
        verified = scrcpy_bridge.verify_server_binary()
        self.assertTrue(verified.is_file())
        self.assertEqual(verified.name, "scrcpy-server")

    def test_verify_server_binary_rejects_missing_or_tampered_file(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing-server"
            with self.assertRaises(scrcpy_bridge.ScrcpyError):
                scrcpy_bridge.verify_server_binary(missing)

            tampered = Path(td) / "tampered-server"
            tampered.write_bytes(b"not-a-valid-scrcpy-server")
            with self.assertRaises(scrcpy_bridge.ScrcpyError):
                scrcpy_bridge.verify_server_binary(tampered)

    def test_parse_adb_forward_port(self):
        self.assertEqual(scrcpy_bridge.parse_adb_forward_port("54321\n"), 54321)
        self.assertEqual(scrcpy_bridge.parse_adb_forward_port("  12345 \r\n"), 12345)
        for bad in ("", "0", "70000", "error: device not found", "-1"):
            with self.assertRaises(scrcpy_bridge.ScrcpyError):
                scrcpy_bridge.parse_adb_forward_port(bad)

    def test_build_server_cmd_presets(self):
        cmd_1080 = scrcpy_bridge.build_server_cmd(0x01ABCDEF, quality="1080", max_fps=60)
        joined = " ".join(cmd_1080)
        self.assertIn("com.genymobile.scrcpy.Server", joined)
        self.assertIn("3.3.4", joined)
        self.assertIn("scid=01abcdef", joined)
        self.assertIn("max_size=1080", joined)
        self.assertIn("max_fps=60", joined)
        self.assertIn("audio=false", joined)
        self.assertIn("tunnel_forward=true", joined)
        self.assertIn("clipboard_autosync=false", joined)

        cmd_720 = scrcpy_bridge.build_server_cmd(0x12, quality="720", max_fps=30)
        self.assertIn("max_size=720", " ".join(cmd_720))
        self.assertIn("video_bit_rate=4000000", " ".join(cmd_720))
        self.assertIn("max_fps=30", " ".join(cmd_720))

        cmd_native = scrcpy_bridge.build_server_cmd(0x12, quality="native", max_fps=60)
        self.assertNotIn("max_size=", " ".join(cmd_native))

        # Samsung Android 12 libstagefright copies /proc/self/cmdline into a fixed 256-byte buffer
        for quality, fps in (("720", 30), ("1080", 60), ("native", 60)):
            proc_args = scrcpy_bridge.build_server_cmd(0x7FFFFFFE, quality=quality, max_fps=fps)[2:]
            cmdline_len = len(" ".join(proc_args))
            self.assertLess(cmdline_len, 220, f"cmdline too long for Samsung ACodec: {cmdline_len}")

    def test_parse_device_video_and_frame_headers(self):
        raw_name = "SM-G9730".encode("utf-8").ljust(64, b"\x00")
        self.assertEqual(scrcpy_bridge.parse_device_meta(raw_name), "SM-G9730")

        vheader = struct.pack(">III", scrcpy_bridge.CODEC_ID_H264, 512, 1080)
        self.assertEqual(scrcpy_bridge.parse_video_header(vheader), (scrcpy_bridge.CODEC_ID_H264, 512, 1080))
        with self.assertRaises(scrcpy_bridge.ScrcpyError):
            scrcpy_bridge.parse_video_header(struct.pack(">III", 0x68323635, 512, 1080))

        cfg_hdr = struct.pack(">QI", scrcpy_bridge.PACKET_FLAG_CONFIG, 42)
        self.assertEqual(scrcpy_bridge.parse_frame_header(cfg_hdr), (True, False, 0, 42))

        kf_hdr = struct.pack(">QI", scrcpy_bridge.PACKET_FLAG_KEY_FRAME | 123456, 4096)
        self.assertEqual(scrcpy_bridge.parse_frame_header(kf_hdr), (False, True, 123456, 4096))

        delta_hdr = struct.pack(">QI", 987654, 1200)
        self.assertEqual(scrcpy_bridge.parse_frame_header(delta_hdr), (False, False, 987654, 1200))

        ws_pkt = scrcpy_bridge.pack_ws_video_packet(False, True, 123456, b"\x00\x00\x00\x01\x65")
        self.assertEqual(ws_pkt[:10], struct.pack(">BBQ", scrcpy_bridge.WS_VIDEO_TYPE, scrcpy_bridge.WS_FLAG_KEYFRAME, 123456))
        self.assertEqual(ws_pkt[10:], b"\x00\x00\x00\x01\x65")

    def test_control_message_binary_encoding(self):
        key_pkt = scrcpy_bridge.pack_inject_keycode(0, 3, repeat=0, meta_state=0)
        self.assertEqual(len(key_pkt), 14)
        self.assertEqual(struct.unpack(">BBiii", key_pkt), (0, 0, 3, 0, 0))

        txt_pkt = scrcpy_bridge.pack_inject_text("hello")
        self.assertEqual(txt_pkt, b"\x01\x00\x00\x00\x05hello")

        touch_down = scrcpy_bridge.pack_inject_touch(0, 256, 540, 512, 1080)
        self.assertEqual(len(touch_down), 32)
        self.assertEqual(
            struct.unpack(">BBqiiHHHii", touch_down),
            (2, 0, -2, 256, 540, 512, 1080, 0xFFFF, 0, 0),
        )
        touch_up = scrcpy_bridge.pack_inject_touch(1, 256, 540, 512, 1080)
        self.assertEqual(struct.unpack(">BBqiiHHHii", touch_up)[7], 0)

        scroll_pkt = scrcpy_bridge.pack_inject_scroll(256, 540, 512, 1080, 0.0, -8.0)
        self.assertEqual(len(scroll_pkt), 21)
        self.assertEqual(struct.unpack(">BiiHHhhi", scroll_pkt), (3, 256, 540, 512, 1080, 0, -16384, 0))

        back_pkt = scrcpy_bridge.pack_back_or_screen_on(0)
        self.assertEqual(back_pkt, b"\x04\x00")

        clip_pkt = scrcpy_bridge.pack_set_clipboard(7, "你好世界", paste=True)
        utf8_cn = "你好世界".encode("utf-8")
        self.assertEqual(clip_pkt[:14], struct.pack(">BQBI", 9, 7, 1, len(utf8_cn)))
        self.assertEqual(clip_pkt[14:], utf8_cn)

        self.assertEqual(scrcpy_bridge.pack_set_display_power(False), b"\x0a\x00")
        self.assertEqual(scrcpy_bridge.pack_set_display_power(True), b"\x0a\x01")
        self.assertEqual(scrcpy_bridge.pack_simple_action(scrcpy_bridge.TYPE_RESET_VIDEO), b"\x11")
        self.assertEqual(scrcpy_bridge.pack_simple_action(scrcpy_bridge.TYPE_ROTATE_DEVICE), b"\x0b")

    def test_encode_control_command_validation(self):
        pkts = scrcpy_bridge.encode_control_command({"type": "key", "keycode": 3, "action": "tap"})
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[0], scrcpy_bridge.pack_inject_keycode(0, 3))
        self.assertEqual(pkts[1], scrcpy_bridge.pack_inject_keycode(1, 3))

        back_pkts = scrcpy_bridge.encode_control_command({"type": "action", "name": "back_or_screen_on"})
        self.assertEqual(back_pkts, [b"\x04\x00", b"\x04\x01"])

        with self.assertRaises(ValueError):
            scrcpy_bridge.encode_control_command({"type": "touch", "action": "down", "x": 10, "y": 10, "width": 0, "height": 100})
        with self.assertRaises(ValueError):
            scrcpy_bridge.encode_control_command({"type": "unknown_cmd"})


class WebSocketTests(unittest.TestCase):
    def _socket_pair(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=3)
        server_side, _ = srv.accept()
        srv.close()
        client.settimeout(3)
        server_side.settimeout(3)
        return client, server_side

    def test_ws_accept_key_matches_rfc6455_vector(self):
        self.assertEqual(
            scrcpy_bridge.ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )

    def test_fragmented_utf8_chinese_text_with_interleaved_ping(self):
        client, server_side = self._socket_pair()
        try:
            ws = scrcpy_bridge.WebSocketConn(server_side)
            text = "你好，DroidBridge 分片测试！"
            raw = text.encode("utf-8")
            # Intentionally split right in the middle of a 3-byte UTF-8 Chinese character
            p1, p2, p3 = raw[:4], raw[4:11], raw[11:]

            client.sendall(_mask_ws_frame(0x1, p1, fin=False))
            client.sendall(_mask_ws_frame(0x9, b"ping-mid", fin=True))
            client.sendall(_mask_ws_frame(0x0, p2, fin=False))
            client.sendall(_mask_ws_frame(0x0, p3, fin=True))

            msg = ws.recv_message()
            self.assertEqual(msg, ("text", text))

            # Server must have replied with Pong carrying the exact Ping payload
            fin, opcode, pong_payload = _read_server_ws_frame(client)
            self.assertTrue(fin)
            self.assertEqual(opcode, 0xA)
            self.assertEqual(pong_payload, b"ping-mid")
        finally:
            client.close()
            server_side.close()

    def test_fragmented_message_exceeding_max_bytes_closes_1009(self):
        client, server_side = self._socket_pair()
        try:
            ws = scrcpy_bridge.WebSocketConn(server_side, max_message_bytes=128)
            client.sendall(_mask_ws_frame(0x1, b"a" * 80, fin=False))
            client.sendall(_mask_ws_frame(0x0, b"b" * 80, fin=True))
            with self.assertRaises(scrcpy_bridge.WebSocketCloseError) as ctx:
                ws.recv_message()
            self.assertEqual(ctx.exception.code, 1009)
            fin, opcode, payload = _read_server_ws_frame(client)
            self.assertTrue(fin)
            self.assertEqual(opcode, 0x8)
            self.assertEqual(struct.unpack("!H", payload[:2])[0], 1009)
        finally:
            client.close()
            server_side.close()

    def test_orphan_continuation_frame_closes_1002(self):
        client, server_side = self._socket_pair()
        try:
            ws = scrcpy_bridge.WebSocketConn(server_side)
            client.sendall(_mask_ws_frame(0x0, b"orphan", fin=True))
            with self.assertRaises(scrcpy_bridge.WebSocketCloseError) as ctx:
                ws.recv_message()
            self.assertEqual(ctx.exception.code, 1002)
            fin, opcode, payload = _read_server_ws_frame(client)
            self.assertTrue(fin)
            self.assertEqual(opcode, 0x8)
            self.assertEqual(struct.unpack("!H", payload[:2])[0], 1002)
        finally:
            client.close()
            server_side.close()

    def test_send_binary_and_text_frames(self):
        client, server_side = self._socket_pair()
        try:
            ws = scrcpy_bridge.WebSocketConn(server_side)
            big_bin = bytes(range(256)) * 20
            ws.send_binary(big_bin)
            ws.send_text('{"ok":true}')

            fin1, op1, d1 = _read_server_ws_frame(client)
            fin2, op2, d2 = _read_server_ws_frame(client)
            self.assertEqual((fin1, op1, d1), (True, 0x2, big_bin))
            self.assertEqual((fin2, op2, d2), (True, 0x1, b'{"ok":true}'))
        finally:
            client.close()
            server_side.close()


class _FakeAdbTool:
    def __init__(self, forward_port: int, serial: str = "FAKE-DEV-1"):
        self.serial = serial
        self.forward_port = forward_port
        self.calls: list[list[str]] = []
        self.forwards: dict[str, str] = {"tcp:5038": "tcp:5038"}

    def resolve(self):
        return ["adb"]

    def online_device(self, serial: str = ""):
        if serial and serial != self.serial:
            raise RuntimeError(f"指定设备 {serial} 未在线")
        return {"serial": self.serial, "state": "device", "model": "FakePhone"}

    def run(self, args):
        args = list(args)
        self.calls.append(args)
        if "push" in args:
            return 0, "1 file pushed", ""
        if "forward" in args and "--remove" in args:
            local = args[-1]
            self.forwards.pop(local, None)
            return 0, "", ""
        if "forward" in args and "tcp:0" in args:
            remote = args[-1]
            self.forwards[f"tcp:{self.forward_port}"] = remote
            return 0, f"{self.forward_port}\n", ""
        return 0, "", ""


class _FakeProc:
    def __init__(self, exit_code=None, stderr_bytes=b""):
        self.returncode = exit_code
        self.terminated = False
        self.killed = False
        self.stdout = None
        self.stderr = _BytesReader(stderr_bytes)

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


class _BytesReader:
    def __init__(self, data: bytes):
        self._data = data
        self._read = False

    def read(self, *_args):
        if self._read:
            return b""
        self._read = True
        return self._data

    def close(self):
        pass


class PhoneMirrorManagerLifecycleTests(unittest.TestCase):
    def _start_fake_scrcpy_server(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        received_controls: list[bytes] = []
        stop_evt = threading.Event()
        control_ready = threading.Event()

        def _serve():
            video_sock = None
            control_sock = None
            try:
                listener.settimeout(5)
                video_sock, _ = listener.accept()
                video_sock.sendall(b"\x00")
                control_sock, _ = listener.accept()
                control_ready.set()

                # Send device name (64B) + codec meta (12B: h264, 512x1080)
                video_sock.sendall("SM-G9730".encode("utf-8").ljust(64, b"\x00"))
                video_sock.sendall(struct.pack(">III", scrcpy_bridge.CODEC_ID_H264, 512, 1080))
                # Send 1 config packet (SPS+PPS) + 1 keyframe packet
                sps = b"\x00\x00\x00\x01\x67\x42\xe0\x1f\x00\x00\x00\x01\x68\xce\x3c\x80"
                idr = b"\x00\x00\x00\x01\x65\x88\x84"
                video_sock.sendall(struct.pack(">QI", scrcpy_bridge.PACKET_FLAG_CONFIG, len(sps)) + sps)
                video_sock.sendall(struct.pack(">QI", scrcpy_bridge.PACKET_FLAG_KEY_FRAME | 1000, len(idr)) + idr)

                # Send a DeviceMessage (TYPE_ACK_CLIPBOARD) to verify backend drains control socket
                control_sock.sendall(struct.pack(">BQ", 1, 99))
                control_sock.settimeout(0.2)
                while not stop_evt.is_set():
                    try:
                        chunk = control_sock.recv(4096)
                        if not chunk:
                            break
                        received_controls.append(chunk)
                        # If client sent TYPE_RESET_VIDEO (0x11), emit another keyframe
                        if b"\x11" in chunk:
                            video_sock.sendall(struct.pack(">QI", scrcpy_bridge.PACKET_FLAG_KEY_FRAME | 2000, len(idr)) + idr)
                    except socket.timeout:
                        continue
            except OSError:
                pass
            finally:
                for s in (video_sock, control_sock, listener):
                    if s is not None:
                        try:
                            s.close()
                        except OSError:
                            pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return port, received_controls, stop_evt, control_ready

    def test_start_stream_screen_off_and_stop_restores_power_and_preserves_proxy_forward(self):
        port, received_controls, stop_evt, _ = self._start_fake_scrcpy_server()
        fake_adb = _FakeAdbTool(forward_port=port)
        fake_proc = _FakeProc()

        manager = scrcpy_bridge.PhoneMirrorManager(
            adb_factory=lambda _cfg: fake_adb,
            popen_fn=lambda *a, **kw: fake_proc,
        )
        try:
            st = manager.start({}, quality="1080", max_fps=60, screen_off=True)
            self.assertTrue(st["running"])
            self.assertEqual(st["serial"], "FAKE-DEV-1")
            self.assertEqual(st["device_name"], "SM-G9730")
            self.assertEqual((st["width"], st["height"]), (512, 1080))
            self.assertTrue(st["screen_off"])
            # Temporary forward added alongside existing proxy forward
            self.assertIn("tcp:5038", fake_adb.forwards)
            self.assertIn(f"tcp:{port}", fake_adb.forwards)

            # Attach a real WebSocket pair and verify initial status, video packets, pause/resume
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            ws_port = srv.getsockname()[1]
            ws_client = socket.create_connection(("127.0.0.1", ws_port), timeout=3)
            ws_server_sock, _ = srv.accept()
            srv.close()
            ws_client.settimeout(3)

            ws_thread = threading.Thread(
                target=manager.handle_websocket,
                args=(scrcpy_bridge.WebSocketConn(ws_server_sock),),
                daemon=True,
            )
            ws_thread.start()

            # Read initial status + config + keyframe
            got_status = None
            got_video = []
            deadline = time.time() + 3.0
            while time.time() < deadline and (got_status is None or len(got_video) < 2):
                fin, op, payload = _read_server_ws_frame(ws_client)
                self.assertTrue(fin)
                if op == 0x1:
                    msg = json.loads(payload.decode("utf-8"))
                    if msg.get("type") == "status":
                        got_status = msg
                elif op == 0x2:
                    got_video.append(payload)

            self.assertIsNotNone(got_status)
            self.assertEqual(got_status["width"], 512)
            self.assertEqual(got_status["height"], 1080)
            self.assertGreaterEqual(len(got_video), 1)
            self.assertEqual(got_video[0][0], scrcpy_bridge.WS_VIDEO_TYPE)

            # Pause then resume should trigger TYPE_RESET_VIDEO (0x11)
            ws_client.sendall(_mask_ws_frame(0x1, json.dumps({"type": "pause", "paused": True}).encode("utf-8")))
            ws_client.sendall(_mask_ws_frame(0x1, json.dumps({"type": "pause", "paused": False}).encode("utf-8")))
            ws_client.sendall(_mask_ws_frame(0x1, json.dumps({"type": "clipboard", "text": "中文测试", "paste": True}).encode("utf-8")))
            ws_client.sendall(_mask_ws_frame(0x8, struct.pack("!H", 1000)))
            ws_thread.join(timeout=3)
            ws_client.close()

            # Stop should restore display power (0x0a 0x01), remove ONLY temp forward, keep tcp:5038
            stopped = manager.stop()
            self.assertFalse(stopped["running"])
            self.assertTrue(fake_proc.terminated)
            self.assertNotIn(f"tcp:{port}", fake_adb.forwards)
            self.assertEqual(fake_adb.forwards.get("tcp:5038"), "tcp:5038")

            all_ctrl = b"".join(received_controls)
            self.assertIn(b"\x0a\x00", all_ctrl)  # screen off sent on start
            self.assertIn(b"\x0a\x01", all_ctrl)  # screen on restored on stop
            self.assertIn("中文测试".encode("utf-8"), all_ctrl)
        finally:
            stop_evt.set()
            manager.shutdown()

    def test_handshake_failure_cleans_up_temp_forward_and_preserves_proxy_forward(self):
        # Allocate a closed port so connection fails immediately while fake proc exits early
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
        s.close()

        fake_adb = _FakeAdbTool(forward_port=dead_port)
        crashed_proc = _FakeProc(exit_code=1, stderr_bytes=b"ERROR: Could not open display\n")

        manager = scrcpy_bridge.PhoneMirrorManager(
            adb_factory=lambda _cfg: fake_adb,
            popen_fn=lambda *a, **kw: crashed_proc,
            handshake_timeout=1.0,
        )
        with self.assertRaises(scrcpy_bridge.ScrcpyError) as ctx:
            manager.start({}, quality="1080", max_fps=60)
        self.assertIn("Could not open display", str(ctx.exception))
        # Temp forward must be cleaned up, proxy forward preserved
        self.assertNotIn(f"tcp:{dead_port}", fake_adb.forwards)
        self.assertEqual(fake_adb.forwards.get("tcp:5038"), "tcp:5038")


class DroidBridgePhoneEndpointTests(unittest.TestCase):
    def setUp(self):
        import droidbridge
        from http.server import ThreadingHTTPServer

        self.db = droidbridge
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), droidbridge.Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.db._phone_mirror.shutdown()
        self.server.shutdown()
        self.server.server_close()

    def _raw_http(self, raw_request: bytes) -> tuple[bytes, socket.socket]:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        sock.settimeout(3)
        sock.sendall(raw_request)
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf), sock

    def test_phone_status_and_ws_upgrade_auth_checks(self):
        import urllib.request

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/phone/status",
            headers={"X-DroidBridge-Token": self.db.API_TOKEN},
        )
        with opener.open(req, timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["running"])
        self.assertTrue(payload["server_ready"])

        # WebSocket with bad token must be rejected with 403
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        bad_req = (
            f"GET /api/phone/ws?token=wrong HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Origin: http://127.0.0.1:{self.port}\r\n"
            f"Connection: close\r\n"
            f"Upgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        resp_bytes, sock = self._raw_http(bad_req)
        sock.close()
        self.assertTrue(resp_bytes.startswith(b"HTTP/1.1 403"))

        # WebSocket with bad origin must be rejected with 403
        bad_origin_req = (
            f"GET /api/phone/ws?token={self.db.API_TOKEN} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Origin: https://evil.example\r\n"
            f"Connection: close\r\n"
            f"Upgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        resp_bytes, sock = self._raw_http(bad_origin_req)
        sock.close()
        self.assertTrue(resp_bytes.startswith(b"HTTP/1.1 403"))

        # Valid WebSocket handshake returns 101 + Sec-WebSocket-Accept + initial status JSON frame
        good_req = (
            f"GET /api/phone/ws?token={self.db.API_TOKEN} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Origin: http://127.0.0.1:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        resp_bytes, sock = self._raw_http(good_req)
        try:
            header_part, sep, leftover = resp_bytes.partition(b"\r\n\r\n")
            self.assertEqual(sep, b"\r\n\r\n")
            self.assertTrue(header_part.startswith(b"HTTP/1.1 101"))
            expected_accept = scrcpy_bridge.ws_accept_key(key).encode("ascii")
            self.assertIn(b"Sec-WebSocket-Accept: " + expected_accept, header_part)

            # Parse first server text frame (may already sit in leftover buffer)
            if leftover:
                b1, b2 = leftover[0], leftover[1]
                length = b2 & 0x7F
                offset = 2
                if length == 126:
                    length = struct.unpack("!H", leftover[2:4])[0]
                    offset = 4
                need = offset + length - len(leftover)
                if need > 0:
                    leftover += _recv_exact(sock, need)
                frame_payload = leftover[offset:offset + length]
                self.assertEqual(b1 & 0x0F, 0x1)
            else:
                fin, op, frame_payload = _read_server_ws_frame(sock)
                self.assertTrue(fin)
                self.assertEqual(op, 0x1)

            status_msg = json.loads(frame_payload.decode("utf-8"))
            self.assertEqual(status_msg["type"], "status")
            self.assertFalse(status_msg["running"])
            sock.sendall(_mask_ws_frame(0x8, struct.pack("!H", 1000)))
        finally:
            sock.close()


if __name__ == "__main__":
    unittest.main()
