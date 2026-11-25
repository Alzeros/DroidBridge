"""Loopback-only routing tests. Run with python -m unittest -v test_routing."""

import http.client
import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import droidbridge


class TestPeer(BaseHTTPRequestHandler):
    """A local origin or a stand-in for the upstream HTTP proxy."""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.command, self.path, body))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        self.server.requests.append((self.command, self.path, b""))
        # The proxy must preserve tunnel data that arrives with the response.
        self.connection.sendall(b"HTTP/1.1 200 OK\r\n\r\nready\n")
        self.wfile.write(self.rfile.readline())


class RoutingTests(unittest.TestCase):
    def serve(self, server):
        worker = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        config_path = root / "config.json"
        self.rules_path = root / "rules.yaml"
        patcher = patch.object(droidbridge, "CONFIG_PATH", config_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin = self.serve(ThreadingHTTPServer(("127.0.0.1", 0), TestPeer))
        self.upstream = self.serve(ThreadingHTTPServer(("127.0.0.1", 0), TestPeer))
        self.origin.requests = []
        self.upstream.requests = []
        self.origin_port = self.origin.server_address[1]
        self.write_rules(
            "DOMAIN,127.0.0.1,DIRECT",
            "MATCH,PROXY",
        )
        config_path.write_text(json.dumps({
            "proxy": {
                "host": "127.0.0.1",
                "port": self.upstream.server_address[1],
                "rules_file": str(self.rules_path),
            },
            "apps": [],
        }), encoding="utf-8")
        self.router = self.serve(droidbridge.ProxyServer(("127.0.0.1", 0), droidbridge.ProxyHandler))

    def write_rules(self, *entries):
        self.rules_path.write_text(
            "rules:\n" + "".join(f"  - {entry}\n" for entry in entries), encoding="utf-8"
        )

    def post(self, host):
        target = f"http://{host}:{self.origin_port}/api?q=1"
        connection = http.client.HTTPConnection(*self.router.server_address, timeout=3)
        try:
            connection.request("POST", target, body=b"prompt")
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def tunnel(self, client, reader, host, port):
        authority = f"{host}:{port}"
        client.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        status = reader.readline().split()
        self.assertEqual(status[1:2], [b"200"])
        while True:
            line = reader.readline()
            self.assertTrue(line, "CONNECT response ended before its headers")
            if line == b"\r\n":
                break

    def test_http_body_and_target_on_each_route(self):
        self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
        self.assertEqual(self.post("localhost"), (200, b"prompt"))
        self.assertEqual(self.origin.requests, [("POST", "/api?q=1", b"prompt")])
        self.assertEqual(self.upstream.requests, [
            ("POST", f"http://localhost:{self.origin_port}/api?q=1", b"prompt")
        ])

    def test_direct_connect_with_client_half_close(self):
        with socket.create_connection(self.router.server_address, timeout=3) as client:
            with client.makefile("rb") as reader:
                self.tunnel(client, reader, "127.0.0.1", self.origin_port)
                client.sendall(b"POST /tunnel HTTP/1.0\r\nContent-Length: 4\r\n\r\nping")
                client.shutdown(socket.SHUT_WR)
                response = reader.read()
        self.assertTrue(response.endswith(b"\r\n\r\nping"), response)
        self.assertEqual(self.origin.requests, [("POST", "/tunnel", b"ping")])
        self.assertEqual(self.upstream.requests, [])

    def test_upstream_connect_preserves_early_data(self):
        with socket.create_connection(self.router.server_address, timeout=3) as client:
            with client.makefile("rb") as reader:
                self.tunnel(client, reader, "localhost", self.origin_port)
                self.assertEqual(reader.readline(), b"ready\n")
                client.sendall(b"through upstream\n")
                self.assertEqual(reader.readline(), b"through upstream\n")
        self.assertEqual(self.upstream.requests, [
            ("CONNECT", f"localhost:{self.origin_port}", b"")
        ])
        self.assertEqual(self.origin.requests, [])

    def test_invalid_rules_stop_forwarding_and_edits_take_effect(self):
        self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
        self.origin.requests.clear()
        self.write_rules("GEOIP,CN,DIRECT", "MATCH,PROXY")
        self.assertEqual(self.post("127.0.0.1")[0], 503)
        self.assertEqual(self.origin.requests, [])
        self.assertEqual(self.upstream.requests, [])
        self.write_rules("MATCH,PROXY")
        self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
        self.assertEqual(self.origin.requests, [])
        self.assertEqual(len(self.upstream.requests), 1)

    def test_ip_cidr_rules_match_ipv4_and_ipv6_boundaries(self):
        self.write_rules(
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,169.254.0.0/16,DIRECT",
            "IP-CIDR,::1/128,DIRECT",
            "IP-CIDR,fc00::/7,DIRECT",
            "IP-CIDR,fe80::/10,DIRECT",
            "MATCH,PROXY",
        )
        table = droidbridge.RouteTable.load(droidbridge.load_config())
        self.assertFalse(table.error)
        for host, expected in [
            ("10.0.0.1", "DIRECT"), ("10.255.255.255", "DIRECT"),
            ("11.0.0.1", "PROXY"),
            ("172.16.0.1", "DIRECT"), ("172.31.255.255", "DIRECT"),
            ("172.15.255.255", "PROXY"), ("172.32.0.1", "PROXY"),
            ("192.168.1.1", "DIRECT"), ("192.169.0.1", "PROXY"),
            ("127.0.0.1", "DIRECT"), ("169.254.1.1", "DIRECT"),
            ("::1", "DIRECT"), ("[::1]", "DIRECT"),
            ("fd00::1", "DIRECT"), ("fe80::1", "DIRECT"),
            ("2001:4860:4860::8888", "PROXY"),
            ("example.com", "PROXY"),
        ]:
            with self.subTest(host=host):
                self.assertEqual(table.action_for(host), expected)

    def test_invalid_ip_cidr_stops_rule_loading(self):
        self.write_rules("IP-CIDR,999.0.0.0/8,DIRECT", "MATCH,PROXY")
        table = droidbridge.RouteTable.load(droidbridge.load_config())
        self.assertTrue(table.error)
        self.assertIn("IP-CIDR", table.error)
        self.assertEqual(table.rules, [])

    def test_first_match_and_domain_suffix_boundaries(self):
        self.write_rules(
            "'DOMAIN,AI.corp.example,PROXY' # first match wins",
            "DOMAIN-SUFFIX,corp.example,DIRECT",
            "DOMAIN-KEYWORD,internal,DIRECT",
            "MATCH,PROXY",
        )
        table = droidbridge.RouteTable.load(droidbridge.load_config())
        self.assertFalse(table.error)
        for host, expected in [
            ("ai.corp.example.", "PROXY"), ("corp.example", "DIRECT"),
            ("api.corp.example", "DIRECT"), ("notcorp.example", "PROXY"),
            ("internal.test", "DIRECT"), ("other.test", "PROXY"),
        ]:
            with self.subTest(host=host):
                self.assertEqual(table.action_for(host), expected)

    def test_route_table_cache_hits_and_invalidates_on_change(self):
        with patch.object(droidbridge.RouteTable, "load", wraps=droidbridge.RouteTable.load) as spy:
            self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
            self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
            self.assertEqual(spy.call_count, 1)
            self.assertEqual(len(self.origin.requests), 2)

            self.write_rules("MATCH,PROXY")
            self.assertEqual(self.post("127.0.0.1"), (200, b"prompt"))
            self.assertEqual(spy.call_count, 2)
            self.assertEqual(len(self.origin.requests), 2)
            self.assertEqual(len(self.upstream.requests), 1)

    def test_chunked_post_forwarded_on_direct_and_proxy(self):
        def _send_chunked(host):
            target = f"http://{host}:{self.origin_port}/chunked"
            raw_req = (
                f"POST {target} HTTP/1.1\r\n"
                f"Host: {host}:{self.origin_port}\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n\r\n"
                "5;ext=1\r\nhello\r\n"
                "6\r\n world\r\n"
                "0\r\nX-Trailer: ignored\r\n\r\n"
            ).encode("ascii")
            with socket.create_connection(self.router.server_address, timeout=3) as sock:
                sock.sendall(raw_req)
                chunks = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            return b"".join(chunks)

        direct_resp = _send_chunked("127.0.0.1")
        proxy_resp = _send_chunked("localhost")
        self.assertTrue(direct_resp.endswith(b"\r\n\r\nhello world"), direct_resp)
        self.assertTrue(proxy_resp.endswith(b"\r\n\r\nhello world"), proxy_resp)
        self.assertEqual(self.origin.requests, [("POST", "/chunked", b"hello world")])
        self.assertEqual(self.upstream.requests, [
            ("POST", f"http://localhost:{self.origin_port}/chunked", b"hello world")
        ])

    def test_detailed_error_recorded_for_upstream_failures(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dead_sock:
            dead_sock.bind(("127.0.0.1", 0))
            dead_port = dead_sock.getsockname()[1]

        self.write_rules(
            f"upstream: http://127.0.0.1:{dead_port}",
        )
        # Re-write with rules block including upstream
        self.rules_path.write_text(
            f"upstream: http://127.0.0.1:{dead_port}\nrules:\n  - MATCH,PROXY\n",
            encoding="utf-8",
        )
        with droidbridge._proxy_events_lock:
            droidbridge._proxy_events.clear()

        with socket.create_connection(self.router.server_address, timeout=3) as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            resp = client.recv(4096).decode("utf-8", errors="replace")
        self.assertIn("502", resp)
        with droidbridge._proxy_events_lock:
            latest = droidbridge._proxy_events[0]
        self.assertFalse(latest["ok"])
        self.assertIn("上游代理拒绝连接", latest["error"])

    def test_rules_helpers_extract_save_and_quick_add(self):
        self.assertEqual(droidbridge.extract_test_host("https://API.cmaiot.cn:8443/v1?a=1"), "api.cmaiot.cn")
        self.assertEqual(droidbridge.extract_test_host("[::1]:8080"), "::1")

        cfg = droidbridge.load_config()
        table = droidbridge.RouteTable.load_from_text("rules:\n  - DOMAIN,a.test,DIRECT\n  - MATCH,PROXY\n", cfg)
        self.assertFalse(table.error)
        rule, idx = table.match_detail("a.test")
        self.assertEqual((rule.action, idx), ("DIRECT", 1))

        bad_table = droidbridge.save_rules_text(cfg, "rules:\n  - GEOIP,CN,DIRECT\n")
        self.assertTrue(bad_table.error)
        # Disk rules remain untouched and valid
        self.assertFalse(droidbridge.RouteTable.load(cfg).error)

        res1 = droidbridge.quick_add_rule(cfg, "foo.example:443", "DIRECT")
        self.assertTrue(res1["ok"] and res1["changed"] and not res1["updated"])
        self.assertEqual(res1["rule"], "DOMAIN,foo.example,DIRECT")
        self.assertEqual(droidbridge.RouteTable.load(cfg).action_for("foo.example"), "DIRECT")

        res_dup = droidbridge.quick_add_rule(cfg, "foo.example", "DIRECT")
        self.assertTrue(res_dup["ok"] and not res_dup["changed"])

        res_upd = droidbridge.quick_add_rule(cfg, "foo.example", "PROXY")
        self.assertTrue(res_upd["ok"] and res_upd["changed"] and res_upd["updated"])
        self.assertEqual(droidbridge.RouteTable.load(cfg).action_for("foo.example"), "PROXY")

        res_ip = droidbridge.quick_add_rule(cfg, "1.2.3.4", "DIRECT")
        self.assertEqual(res_ip["rule"], "IP-CIDR,1.2.3.4/32,DIRECT")

    def test_firefox_profile_discovery_and_sync(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            appdata = base / "AppData"
            ff_root = appdata / "Mozilla" / "Firefox"
            rel_prof = ff_root / "Profiles" / "rel.default-release"
            old_prof = ff_root / "Profiles" / "old.default"
            (rel_prof / "extensions").mkdir(parents=True)
            old_prof.mkdir(parents=True)

            (ff_root / "profiles.ini").write_text(
                "[Install123]\nDefault=Profiles/rel.default-release\n\n"
                "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/old.default\nDefault=1\n",
                encoding="utf-8",
            )
            discovered = droidbridge.discover_firefox_default_profile(
                r"C:\Program Files\Mozilla Firefox\firefox.exe", appdata_dir=str(appdata)
            )
            self.assertEqual(discovered, rel_prof)

            (rel_prof / "cookies.sqlite").write_bytes(b"sqlite")
            (rel_prof / "extensions" / "ext@example.xpi").write_bytes(b"xpi")
            (rel_prof / "addonStartup.json.lz4").write_bytes(b"cache")
            (rel_prof / "parent.lock").write_bytes(b"")
            src_escaped = str(rel_prof).replace("\\", "\\\\")
            (rel_prof / "pkcs11.txt").write_text(f"configdir='sql:{src_escaped}'\n", encoding="utf-8")
            (rel_prof / "extensions.json").write_text(
                json.dumps({"addons": [{"path": str(rel_prof / "extensions" / "ext@example.xpi"), "rootURI": rel_prof.as_uri()}]}),
                encoding="utf-8",
            )

            profiles_dir = base / "profiles"
            cfg = {
                "proxy": {"host": "127.0.0.1", "port": 5038, "listen_host": "127.0.0.1", "listen_port": 10086, "enabled": True},
                "apps": [],
            }
            app = {"id": "ff_1", "name": "FireFox", "exe": r"C:\Program Files\Mozilla Firefox\firefox.exe", "args": "", "kind": "firefox"}
            with patch.object(droidbridge, "PROFILES_DIR", profiles_dir):
                res = droidbridge.sync_firefox_profile(app, cfg, source_dir=rel_prof)
                self.assertTrue(res["ok"], res)
                self.assertEqual(res["extensions"], 1)
                dst = profiles_dir / "ff_1"
                self.assertTrue((dst / "cookies.sqlite").is_file())
                self.assertFalse((dst / "addonStartup.json.lz4").exists())
                self.assertFalse((dst / "parent.lock").exists())
                self.assertIn(str(dst).replace("\\", "\\\\"), (dst / "pkcs11.txt").read_text(encoding="utf-8"))
                self.assertNotIn("rel.default-release", (dst / "extensions.json").read_text(encoding="utf-8"))
                self.assertIn("10086", (dst / "user.js").read_text(encoding="utf-8"))

                with patch.object(droidbridge, "is_firefox_profile_locked", return_value=True):
                    blocked = droidbridge.sync_firefox_profile(app, cfg, source_dir=rel_prof)
                    self.assertFalse(blocked["ok"])

    def test_tray_controller_message_loop_and_cleanup(self):
        if droidbridge.os.name != "nt":
            self.skipTest("Windows-only tray test")
        calls = []
        opened = threading.Event()
        toggled = threading.Event()
        tray = droidbridge.TrayController(
            on_open=lambda: (calls.append("open"), opened.set()),
            on_toggle_proxy=lambda: (calls.append("toggle"), toggled.set()),
            on_quit=lambda: calls.append("quit"),
            is_proxy_enabled=lambda: True,
            tooltip="DroidBridge Test",
        )
        with patch.object(droidbridge._shell32, "Shell_NotifyIconW", return_value=1):
            started = tray.start(timeout=2.0)
            self.assertTrue(started)
            self.assertTrue(tray.active)
            tray.update_tooltip("DroidBridge Updated")
            droidbridge._user32.PostMessageW(tray._hwnd, tray.WM_COMMAND, tray.CMD_OPEN, 0)
            droidbridge._user32.PostMessageW(tray._hwnd, tray.WM_COMMAND, tray.CMD_TOGGLE_PROXY, 0)
            self.assertTrue(opened.wait(timeout=2.0))
            self.assertTrue(toggled.wait(timeout=2.0))
            tray.stop()
        self.assertFalse(tray.active)
        self.assertEqual(calls, ["open", "toggle"])


class SingleRouteInjectionTests(unittest.TestCase):
    def config(self):
        return {
            "proxy": {
                "host": "127.0.0.1",
                "port": 5038,
                "listen_host": "127.0.0.1",
                "listen_port": 10086,
                "rules_file": "rules.yaml",
                "enabled": True,
            },
            "apps": [],
        }

    def test_all_injection_targets_use_local_router(self):
        cfg = self.config()
        cfg["proxy"]["router_enabled"] = False
        cfg["proxy"]["bypass"] = ["localhost", "*.corp.example"]

        self.assertEqual(droidbridge.proxy_url(cfg), "http://127.0.0.1:10086")
        self.assertEqual(droidbridge.proxy_probe_target(cfg), ("127.0.0.1", 10086))

        _, env = droidbridge.build_env(cfg)
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:10086")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:10086")
        self.assertEqual(env["ALL_PROXY"], "http://127.0.0.1:10086")
        self.assertEqual(env["NO_PROXY"], "")

        app = {"exe": r"C:\Apps\Chat\Chat.exe", "args": "", "kind": "electron"}
        cmd, kind, injected = droidbridge.build_cmd(app, cfg)
        self.assertEqual(kind, "electron")
        self.assertIn("--proxy-server=http://127.0.0.1:10086", cmd)
        self.assertIn("--proxy-server", injected)
        self.assertFalse(any(arg.startswith("--proxy-bypass-list") for arg in cmd))

    def test_firefox_prefs_have_no_second_exception_path(self):
        text, summary = droidbridge.build_firefox_user_js(self.config())
        self.assertIn('user_pref("network.proxy.http", "127.0.0.1");', text)
        self.assertIn('user_pref("network.proxy.http_port", 10086);', text)
        self.assertIn('user_pref("network.proxy.no_proxies_on", "");', text)
        self.assertIn("http/ssl=127.0.0.1:10086", summary)

    def test_legacy_config_fields_are_removed_on_load(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps({
                "proxy": {
                    "host": "127.0.0.1",
                    "port": 5038,
                    "listen_host": "127.0.0.1",
                    "listen_port": 10086,
                    "rules_file": str(Path(directory) / "rules.yaml"),
                    "router_enabled": False,
                    "bypass": ["localhost", "*.corp.example"],
                },
                "apps": [{
                    "id": "legacy",
                    "name": "Legacy",
                    "exe": r"C:\Apps\Legacy.exe",
                    "bypass": ["internal.example"],
                }],
            }), encoding="utf-8")
            with patch.object(droidbridge, "CONFIG_PATH", config_path):
                cfg = droidbridge.load_config()

            self.assertNotIn("router_enabled", cfg["proxy"])
            self.assertNotIn("bypass", cfg["proxy"])
            self.assertNotIn("bypass", cfg["apps"][0])
            persisted = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertNotIn("router_enabled", persisted["proxy"])
            self.assertNotIn("bypass", persisted["proxy"])
            self.assertNotIn("bypass", persisted["apps"][0])

    def test_proxy_events_retention_cap_and_clear(self):
        droidbridge.clear_proxy_events()
        self.assertGreaterEqual(droidbridge.MAX_PROXY_EVENTS, 300)
        total = droidbridge.MAX_PROXY_EVENTS + 25
        for idx in range(total):
            droidbridge._record_proxy_event(f"host-{idx}.example", "DIRECT", ok=True, rule="MATCH,DIRECT")

        with droidbridge._proxy_events_lock:
            snapshot = list(droidbridge._proxy_events)
        self.assertEqual(len(snapshot), droidbridge.MAX_PROXY_EVENTS)
        self.assertEqual(snapshot[0]["host"], f"host-{total - 1}.example")
        self.assertEqual(snapshot[-1]["host"], "host-25.example")

        cleared = droidbridge.clear_proxy_events()
        self.assertEqual(cleared, droidbridge.MAX_PROXY_EVENTS)
        with droidbridge._proxy_events_lock:
            self.assertEqual(droidbridge._proxy_events, [])

    def test_query_exit_ip_success_offline_and_invalid(self):
        cfg = self.config()

        class FakeResp:
            def __init__(self, body: bytes):
                self._body = body

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, _limit=-1):
                return self._body

        captured = {}

        class FakeOpener:
            def __init__(self, responses):
                self._responses = list(responses)

            def open(self, req, timeout=None):
                captured.setdefault("urls", []).append(req.full_url)
                captured["ua"] = req.get_header("User-agent")
                captured["timeout"] = timeout
                nxt = self._responses.pop(0)
                if isinstance(nxt, Exception):
                    raise nxt
                return FakeResp(nxt)

        with patch.object(droidbridge, "probe_proxy", return_value=(False, 1)):
            offline = droidbridge.query_exit_ip(cfg)
        self.assertFalse(offline["ok"])
        self.assertIn("离线", offline["error"])

        seen_proxies = {}
        real_proxy_handler = droidbridge.urllib.request.ProxyHandler

        def fake_proxy_handler(proxies):
            seen_proxies.update(proxies)
            return real_proxy_handler(proxies)

        geo_payload = json.dumps({
            "ip": "87.86.22.214",
            "country_code": "JP",
            "country": "Japan",
            "region": "Tokyo",
            "city": "Tokyo",
            "isp": "HYW",
            "asn": 11421,
            "timezone": "Asia/Tokyo",
        }).encode("utf-8")
        with (
            patch.object(droidbridge, "probe_proxy", return_value=(True, 2)),
            patch.object(droidbridge.urllib.request, "ProxyHandler", side_effect=fake_proxy_handler),
            patch.object(droidbridge.urllib.request, "build_opener", return_value=FakeOpener([geo_payload])),
        ):
            ok_geo = droidbridge.query_exit_ip(cfg)
        self.assertTrue(ok_geo["ok"])
        self.assertEqual(ok_geo["ip"], "87.86.22.214")
        self.assertEqual(ok_geo["country_code"], "JP")
        self.assertEqual(ok_geo["location"], "Japan, Tokyo")
        self.assertEqual(ok_geo["isp"], "HYW")
        self.assertEqual(ok_geo["asn"], 11421)
        self.assertEqual(captured["urls"][-1], "https://api.ip.sb/geoip")
        self.assertEqual(seen_proxies["https"], "http://127.0.0.1:5038")

        # Fallback to /ip plain-text IPv6 when /geoip returns non-JSON error page
        with (
            patch.object(droidbridge, "probe_proxy", return_value=(True, 2)),
            patch.object(droidbridge.urllib.request, "build_opener", return_value=FakeOpener([b"<html>502</html>", b"2001:db8::1\n"])),
        ):
            ok_fallback = droidbridge.query_exit_ip(cfg)
        self.assertTrue(ok_fallback["ok"])
        self.assertEqual(ok_fallback["ip"], "2001:db8::1")
        self.assertEqual(ok_fallback["source"], "https://api.ip.sb/ip")
        self.assertEqual(ok_fallback["location"], "")

        with (
            patch.object(droidbridge, "probe_proxy", return_value=(True, 2)),
            patch.object(droidbridge.urllib.request, "build_opener", return_value=FakeOpener([b"<html>error</html>", b"not-an-ip"])),
        ):
            bad_body = droidbridge.query_exit_ip(cfg)
        self.assertFalse(bad_body["ok"])
        self.assertIn("异常", bad_body["error"])

        with (
            patch.object(droidbridge, "probe_proxy", return_value=(True, 2)),
            patch.object(droidbridge.urllib.request, "build_opener", return_value=FakeOpener([TimeoutError("timed out")])),
        ):
            timed_out = droidbridge.query_exit_ip(cfg)
        self.assertFalse(timed_out["ok"])
        self.assertIn("超时", timed_out["error"])


if __name__ == "__main__":
    unittest.main()
