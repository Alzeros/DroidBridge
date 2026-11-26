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
            # Idempotent unregister after close
            reg.unregister(c1.id)
            reg.unregister(c2.id)
        finally:
            for s in (l1, r1, l2, r2):
                try:
                    s.close()
                except OSError:
                    pass

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
        finally:
            t1.close()
            t2.close()


if __name__ == "__main__":
    unittest.main()
