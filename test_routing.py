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


if __name__ == "__main__":
    unittest.main()
