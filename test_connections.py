import json
import os
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import conn_tracker


def _socket_pair():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    left = socket.create_connection(("127.0.0.1", port), timeout=3)
    right, _ = srv.accept()
    srv.close()
    left.settimeout(2)
    right.settimeout(2)
    return left, right


class ConnectionTrackerUnitTests(unittest.TestCase):
    def test_registry_tracks_bytes_snapshot_and_closes_sockets(self):
        reg = conn_tracker.ConnectionRegistry(owner_resolver=lambda *_args: (4242, "Mirasim.exe", r"C:\Apps\Mirasim.exe"))
        l1, r1 = _socket_pair()
        l2, r2 = _socket_pair()
        try:
            c1 = reg.register(
                host="api.example.com",
                port=443,
                protocol="HTTPS",
                action="PROXY",
                rule="DOMAIN-SUFFIX,example.com,PROXY",
                client_addr=("127.0.0.1", 50001),
                server_port=10086,
                left_sock=l1,
                right_sock=r1,
            )
            c1.add_tx(512)
            c1.add_rx(2048)

            c2 = reg.register(
                host="10.0.0.5",
                port=80,
                protocol="HTTP",
                action="DIRECT",
                rule="IP-CIDR,10.0.0.0/8,DIRECT",
                client_addr=("127.0.0.1", 50002),
                server_port=10086,
                left_sock=l2,
                right_sock=r2,
            )
            c2.add_tx(128)
            c2.add_rx(256)

            snap = reg.snapshot()
            self.assertEqual(snap["total"], 2)
            self.assertEqual(snap["total_tx"], 640)
            self.assertEqual(snap["total_rx"], 2304)
            # Newest connection first
            self.assertEqual([row["id"] for row in snap["connections"]], [c2.id, c1.id])
            by_id = {row["id"]: row for row in snap["connections"]}
            self.assertEqual(by_id[c1.id]["pid"], 4242)
            self.assertEqual(by_id[c1.id]["process"], "Mirasim.exe")
            self.assertEqual(by_id[c1.id]["target"], "api.example.com:443")
            self.assertEqual(by_id[c1.id]["tx_bytes"], 512)
            self.assertEqual(by_id[c1.id]["rx_bytes"], 2048)
            self.assertTrue(by_id[c1.id]["active"])

            # Close single connection
            self.assertEqual(reg.close_one(c1.id), 1)
            self.assertEqual(reg.close_one("nonexistent"), 0)
            self.assertEqual(reg.snapshot()["total"], 1)

            # Close all remaining connections
            self.assertEqual(reg.close_all(), 1)
            self.assertEqual(reg.snapshot()["total"], 0)
            # Cumulative stats survive disconnect until explicitly reset
            after_close = reg.snapshot()
            self.assertEqual(after_close["cumulative_tx"], 640)
            self.assertEqual(after_close["cumulative_rx"], 2304)
            self.assertEqual(len(after_close["process_stats"]), 1)
            self.assertEqual(after_close["process_stats"][0]["tx_bytes"], 640)
            self.assertEqual(after_close["process_stats"][0]["rx_bytes"], 2304)
            self.assertEqual(after_close["process_stats"][0]["conn_count"], 2)
            self.assertGreater(after_close["rx_bps"], 0)
            # Reset cumulative stats clears history and zeroes counters
            reg.reset_stats()
            after_reset = reg.snapshot()
            self.assertEqual(after_reset["cumulative_tx"], 0)
            self.assertEqual(after_reset["cumulative_rx"], 0)
            self.assertEqual(after_reset["process_stats"], [])
            # Idempotent unregister after close
            reg.unregister(c1.id)
            reg.unregister(c2.id)
        finally:
            for s in (l1, r1, l2, r2):
                try:
                    s.close()
                except OSError:
                    pass

    def test_sliding_rate_meter_accumulates_and_expires(self):
        meter = conn_tracker._SlidingRateMeter()
        meter.add(4000, 8000, 100.0)
        meter.add(2000, 4000, 100.5)
        self.assertEqual(meter.rate(100.6, window_s=2.0), (3000, 6000))
        # After 2.0s window expires, rate drops cleanly to zero
        self.assertEqual(meter.rate(103.0, window_s=2.0), (0, 0))

    def test_resolve_process_ancestors_walks_tree_and_guards_cycles_and_pid_reuse(self):
        tree = {
            13608: (24724, "agy.EXE"),
            24724: (12196, "Mirasim.exe"),
            12196: (1000, "Mirasim.exe"),
            1000: (0, "explorer.exe"),
            # PID reuse case: child 2000 started at t=100, ppid 999 started later at t=500
            2000: (999, "orphan.exe"),
            999: (1000, "reused.exe"),
            # Cycle case: 10 -> 20 -> 10
            10: (20, "a.exe"),
            20: (10, "b.exe"),
        }
        meta = {
            13608: ("agy.EXE", r"C:\Users\SR\.mirasim\agents\antigravity\current\bin\agy.EXE", 500),
            24724: ("Mirasim.exe", r"C:\Apps\Mirasim.exe", 300),
            12196: ("Mirasim.exe", r"C:\Apps\Mirasim.exe", 200),
            1000: ("explorer.exe", r"C:\Windows\explorer.exe", 100),
            2000: ("orphan.exe", r"C:\Apps\orphan.exe", 100),
            999: ("reused.exe", r"C:\Apps\reused.exe", 500),
            10: ("a.exe", r"C:\Apps\a.exe", 200),
            20: ("b.exe", r"C:\Apps\b.exe", 100),
        }
        anc = conn_tracker.resolve_process_ancestors(
            13608,
            _tree_provider=lambda _force: tree,
            _meta_provider=lambda pid: meta.get(pid, ("", "", 0)),
        )
        self.assertEqual(
            anc,
            [
                {"pid": 24724, "process": "Mirasim.exe", "process_path": r"C:\Apps\Mirasim.exe"},
                {"pid": 12196, "process": "Mirasim.exe", "process_path": r"C:\Apps\Mirasim.exe"},
                {"pid": 1000, "process": "explorer.exe", "process_path": r"C:\Windows\explorer.exe"},
            ],
        )

        # Recycled parent PID (created after child) must stop the walk
        self.assertEqual(
            conn_tracker.resolve_process_ancestors(
                2000,
                _tree_provider=lambda _force: tree,
                _meta_provider=lambda pid: meta.get(pid, ("", "", 0)),
            ),
            [],
        )

        # Cyclic parent reference must terminate cleanly
        self.assertEqual(
            conn_tracker.resolve_process_ancestors(
                10,
                _tree_provider=lambda _force: tree,
                _meta_provider=lambda pid: meta.get(pid, ("", "", 0)),
            ),
            [{"pid": 20, "process": "b.exe", "process_path": r"C:\Apps\b.exe"}],
        )

        # ConnectionRegistry attaches ancestors to snapshot rows
        reg = conn_tracker.ConnectionRegistry(
            owner_resolver=lambda *_args: (13608, "agy.EXE", r"C:\Users\SR\.mirasim\agents\antigravity\current\bin\agy.EXE"),
            ancestor_resolver=lambda _pid: [{"pid": 24724, "process": "Mirasim.exe", "process_path": r"C:\Apps\Mirasim.exe"}],
        )
        c = reg.register(
            host="daily-cloudcode-pa.googleapis.com",
            port=443,
            protocol="HTTPS",
            action="PROXY",
            rule="MATCH,PROXY",
            client_addr=("127.0.0.1", 51000),
            server_port=10086,
            left_sock=None,
            right_sock=None,
        )
        snap = reg.snapshot()
        self.assertEqual(snap["connections"][0]["id"], c.id)
        self.assertEqual(
            snap["connections"][0]["ancestors"],
            [{"pid": 24724, "process": "Mirasim.exe", "process_path": r"C:\Apps\Mirasim.exe"}],
        )

    def test_early_owner_info_and_zero_byte_anonymous_pruning(self):
        # Simulate client socket closing during upstream handshake: early resolve finds chrome.exe, later returns empty
        alive = {"open": True}

        def _resolver(_addr, _port):
            if alive["open"]:
                return 8888, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            return 0, "", ""

        reg = conn_tracker.ConnectionRegistry(owner_resolver=_resolver, ancestor_resolver=lambda _pid: [])
        early_owner = reg.resolve_owner(("127.0.0.1", 55001), 10086)
        alive["open"] = False

        c_chrome = reg.register(
            host="cdn.example.com",
            port=443,
            protocol="HTTPS",
            action="PROXY",
            rule="MATCH,,PROXY",
            client_addr=("127.0.0.1", 55001),
            server_port=10086,
            left_sock=None,
            right_sock=None,
            owner_info=early_owner,
        )
        self.assertEqual(c_chrome.pid, 8888)
        self.assertEqual(c_chrome.process, "chrome.exe")
        reg.unregister(c_chrome.id)

        # Zero-byte anonymous ghost connection is pruned from process_stats upon unregister
        c_ghost = reg.register(
            host="probe.example.com",
            port=443,
            protocol="HTTPS",
            action="PROXY",
            rule="MATCH,,PROXY",
            client_addr=("127.0.0.1", 55002),
            server_port=10086,
            left_sock=None,
            right_sock=None,
        )
        self.assertEqual(c_ghost.pid, 0)
        self.assertEqual(c_ghost.process, "")
        reg.unregister(c_ghost.id)
        snap = reg.snapshot()
        self.assertEqual([s["process"] for s in snap["process_stats"]], ["chrome.exe"])

        # Unknown-process connection with real traffic IS kept in process_stats
        c_real_unknown = reg.register(
            host="real.example.com",
            port=443,
            protocol="HTTPS",
            action="PROXY",
            rule="MATCH,,PROXY",
            client_addr=("127.0.0.1", 55003),
            server_port=10086,
            left_sock=None,
            right_sock=None,
        )
        c_real_unknown.add_rx(512)
        reg.unregister(c_real_unknown.id)
        snap2 = reg.snapshot()
        anon_rows = [s for s in snap2["process_stats"] if not s["process"]]
        self.assertEqual(len(anon_rows), 1)
        self.assertEqual(anon_rows[0]["rx_bytes"], 512)

    @unittest.skipUnless(os.name == "nt", "Windows Toolhelp32 ancestor lookup")
    def test_windows_resolve_process_ancestors_finds_parent_of_current_process(self):
        anc = conn_tracker.resolve_process_ancestors(os.getpid())
        self.assertIsInstance(anc, list)
        self.assertGreaterEqual(len(anc), 1)
        self.assertGreater(anc[0]["pid"], 0)
        self.assertTrue(anc[0]["process"])

    @unittest.skipUnless(os.name == "nt", "Windows GetExtendedTcpTable process lookup")
    def test_windows_resolve_local_tcp_owner_identifies_current_python_process(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv_port = srv.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", srv_port), timeout=3)
        accepted, client_addr = srv.accept()
        try:
            pid, proc_name, proc_path = conn_tracker.resolve_local_tcp_owner(
                client_addr,
                srv_port,
                exclude_pid=0,  # test explicitly connects from our own PID
            )
            self.assertEqual(pid, os.getpid())
            self.assertTrue(proc_name.lower().startswith("python"), f"unexpected proc_name: {proc_name}")
            self.assertTrue(proc_path.lower().endswith(".exe"), f"unexpected proc_path: {proc_path}")
        finally:
            client.close()
            accepted.close()
            srv.close()


class DroidBridgeActiveConnectionsIntegrationTests(unittest.TestCase):
    def setUp(self):
        import droidbridge

        self.db = droidbridge
        # Start a local echo server representing a long-lived HTTPS tunnel target
        self.echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.echo_srv.bind(("127.0.0.1", 0))
        self.echo_srv.listen(4)
        self.echo_port = self.echo_srv.getsockname()[1]
        self.echo_stop = threading.Event()
        self.echo_socks = []

        def _echo_loop():
            self.echo_srv.settimeout(0.2)
            while not self.echo_stop.is_set():
                try:
                    conn, _ = self.echo_srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.echo_socks.append(conn)
                threading.Thread(target=self._handle_echo, args=(conn,), daemon=True).start()

        threading.Thread(target=_echo_loop, daemon=True).start()

        # Start an isolated ProxyServer whose RouteTable routes everything DIRECT
        class _DirectTable:
            error = ""
            upstream = ("127.0.0.1", 5038)

            def rule_for(self, _host):
                return droidbridge.RouteRule("MATCH", "", "DIRECT")

        self.proxy_srv = droidbridge.ProxyServer(("127.0.0.1", 0), droidbridge.ProxyHandler)
        self.proxy_srv.route_table = lambda: _DirectTable()
        self.proxy_port = self.proxy_srv.server_address[1]
        threading.Thread(target=self.proxy_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        # Start DroidBridge HTTP API server
        self.api_srv = ThreadingHTTPServer(("127.0.0.1", 0), droidbridge.Handler)
        self.api_srv.daemon_threads = True
        self.api_port = self.api_srv.server_address[1]
        threading.Thread(target=self.api_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _handle_echo(self, conn: socket.socket):
        conn.settimeout(0.2)
        try:
            while not self.echo_stop.is_set():
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def tearDown(self):
        self.echo_stop.set()
        self.db._conn_registry.close_all()
        self.api_srv.shutdown()
        self.api_srv.server_close()
        self.proxy_srv.shutdown()
        self.proxy_srv.server_close()
        for s in self.echo_socks:
            try:
                s.close()
            except OSError:
                pass
        try:
            self.echo_srv.close()
        except OSError:
            pass

    def _api(self, path: str, body=None, token: str | None = None):
        hdrs = {
            "X-DroidBridge-Token": self.db.API_TOKEN if token is None else token,
            "Origin": f"http://127.0.0.1:{self.api_port}",
        }
        data = None
        if body is not None:
            hdrs["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(f"http://127.0.0.1:{self.api_port}{path}", data=data, headers=hdrs)
        with self.opener.open(req, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _open_connect_tunnel(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3)
        sock.settimeout(2)
        target = f"127.0.0.1:{self.echo_port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
        return sock

    def test_live_connect_tunnel_is_listed_and_force_closed_via_api(self):
        # Auth check
        with self.assertRaises(urllib.error.HTTPError) as err_ctx:
            self._api("/api/connections", token="bad-token")
        self.assertEqual(err_ctx.exception.code, 403)
        err_ctx.exception.close()

        t1 = self._open_connect_tunnel()
        t2 = self._open_connect_tunnel()
        try:
            t1.sendall(b"ping-droidbridge")
            self.assertEqual(t1.recv(64), b"ping-droidbridge")
            t2.sendall(b"hello-2")
            self.assertEqual(t2.recv(64), b"hello-2")

            res = self._api("/api/connections")
            self.assertTrue(res["ok"])
            self.assertEqual(res["total"], 2)
            row = next(r for r in res["connections"] if r["tx_bytes"] >= len(b"ping-droidbridge"))
            self.assertEqual(row["protocol"], "HTTPS")
            self.assertEqual(row["action"], "DIRECT")
            self.assertEqual(row["port"], self.echo_port)
            self.assertGreaterEqual(row["tx_bytes"], len(b"ping-droidbridge"))
            self.assertGreaterEqual(row["rx_bytes"], len(b"ping-droidbridge"))

            # Close single tunnel via API and verify client socket immediately sees EOF/error
            closed = self._api("/api/connections/close", {"id": row["id"]})
            self.assertTrue(closed["ok"])
            self.assertEqual(closed["closed"], 1)
            self.assertEqual(closed["total"], 1)

            deadline = time.time() + 2.0
            got_closed = False
            while time.time() < deadline:
                try:
                    t1.settimeout(0.3)
                    chunk = t1.recv(64)
                    if chunk == b"":
                        got_closed = True
                        break
                except OSError:
                    got_closed = True
                    break
            self.assertTrue(got_closed, "force-closed tunnel socket did not close promptly")

            # Close all remaining tunnels
            closed_all = self._api("/api/connections/close", {"all": True})
            self.assertTrue(closed_all["ok"])
            self.assertEqual(closed_all["closed"], 1)
            self.assertEqual(closed_all["total"], 0)
            self.assertGreaterEqual(closed_all["cumulative_tx"], len(b"ping-droidbridge") + len(b"hello-2"))
            self.assertGreaterEqual(closed_all["cumulative_rx"], len(b"ping-droidbridge") + len(b"hello-2"))
            self.assertTrue(closed_all["process_stats"])

            # Reset cumulative stats via API
            reset = self._api("/api/connections/reset-stats", {})
            self.assertTrue(reset["ok"])
            self.assertEqual(reset["cumulative_tx"], 0)
            self.assertEqual(reset["cumulative_rx"], 0)
            self.assertEqual(reset["process_stats"], [])
        finally:
            t1.close()
            t2.close()


if __name__ == "__main__":
    unittest.main()
