import io
import os
import socket
import stat
import tempfile
import threading
import time
import unittest

from postfix_dane_policy import server as srv


class StaticPolicy:
    def __init__(self, replies):
        self.replies = replies

    def lookup(self, key):
        if key == "boom.de":
            raise RuntimeError("kaputt")
        return self.replies.get(key, "NOTFOUND ")


class NetstringTests(unittest.TestCase):
    def test_roundtrip(self):
        enc = srv.encode_netstring("dane example.de")
        self.assertEqual(enc, b"15:dane example.de,")
        self.assertEqual(srv.read_netstring(io.BytesIO(enc)), b"dane example.de")

    def test_first_byte_already_read(self):
        # the handler reads the first byte itself to switch from idle to request timeout
        self.assertEqual(srv.read_netstring(io.BytesIO(b":abc,"), first=b"3"), b"abc")

    def test_eof_and_errors(self):
        self.assertIsNone(srv.read_netstring(io.BytesIO(b"")))
        for bad in [b"5:abc", b"x:abc,", b"3:abcX", b"99999999:a,", b"12", b":abc,"]:
            with self.assertRaises(ValueError, msg=bad):
                srv.read_netstring(io.BytesIO(bad))

    def test_multiple_requests_on_one_stream(self):
        stream = io.BytesIO(srv.encode_netstring("dane a.de") + srv.encode_netstring("dane b.de"))
        self.assertEqual(srv.read_netstring(stream), b"dane a.de")
        self.assertEqual(srv.read_netstring(stream), b"dane b.de")
        self.assertIsNone(srv.read_netstring(stream))


class HandleRequestTests(unittest.TestCase):
    def setUp(self):
        self.policy = StaticPolicy({"ex.de": "OK dane-only"})

    def test_ok(self):
        self.assertEqual(srv.handle_request(self.policy, "dane", b"dane ex.de"), "OK dane-only")

    def test_wrong_map(self):
        self.assertEqual(srv.handle_request(self.policy, "dane", b"other ex.de"), "PERM unknown map")

    def test_bad_encoding(self):
        self.assertTrue(srv.handle_request(self.policy, "dane", b"\xff\xfe").startswith("PERM"))

    def test_exception_becomes_temp(self):
        self.assertEqual(srv.handle_request(self.policy, "dane", b"dane boom.de"),
                         "TEMP internal error")


def _ask(sock, payload):
    sock.sendall(srv.encode_netstring(payload))
    return srv.read_netstring(sock.makefile("rb")).decode()


class _ServerTestBase(unittest.TestCase):
    def start(self, server):
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()


class TcpServerTests(_ServerTestBase):
    """End-to-end over a real socket, like Postfix talks to the service."""

    def setUp(self):
        self.start(srv.SocketmapServer(("127.0.0.1", 0), StaticPolicy({"ex.de": "OK dane-only"}),
                                       "dane"))
        self.port = self.server.server_address[1]

    def test_persistent_connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            self.assertEqual(_ask(sock, "dane ex.de"), "OK dane-only")
            self.assertEqual(_ask(sock, "dane other.de"), "NOTFOUND ")

    def test_garbage_closes_connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"garbage")
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(100), b"")

    def test_slow_request_is_cut_off(self):
        self.server.request_timeout = 0.5
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"10:dane")          # incomplete request, then silence
            start = time.monotonic()
            self.assertEqual(sock.recv(100), b"")
            self.assertLess(time.monotonic() - start, 3)

    def test_idle_connection_is_closed(self):
        self.server.idle_timeout = 0.5
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            self.assertEqual(sock.recv(100), b"")

    def test_connection_limit(self):
        self.server.max_connections = 1
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as first:
            self.assertEqual(_ask(first, "dane ex.de"), "OK dane-only")
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as second:
                second.sendall(srv.encode_netstring("dane ex.de"))
                self.assertEqual(second.recv(100), b"")
        # after the first connection is gone a new one is accepted again
        deadline = time.monotonic() + 3
        while self.server._active and time.monotonic() < deadline:
            time.sleep(0.05)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as third:
            self.assertEqual(_ask(third, "dane ex.de"), "OK dane-only")


class UnixServerTests(_ServerTestBase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: os.rmdir(self.dir))
        self.path = os.path.join(self.dir, "policy.sock")

    def test_roundtrip_and_cleanup(self):
        server = srv.UnixSocketmapServer(self.path, StaticPolicy({"ex.de": "OK dane-only"}), "dane")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertTrue(stat.S_ISSOCK(os.stat(self.path).st_mode))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(self.path)
                self.assertEqual(_ask(sock, "dane ex.de"), "OK dane-only")
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(os.path.exists(self.path))

    def test_stale_socket_is_replaced(self):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(self.path)
        stale.close()
        self.start(srv.UnixSocketmapServer(self.path, StaticPolicy({}), "dane"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(self.path)
            self.assertEqual(_ask(sock, "dane x.de"), "NOTFOUND ")

    def test_refuses_non_socket_path(self):
        with open(self.path, "w") as fh:
            fh.write("not a socket")
        self.addCleanup(lambda: os.unlink(self.path))
        with self.assertRaises(RuntimeError):
            srv.UnixSocketmapServer(self.path, StaticPolicy({}), "dane")


def _ipv6_loopback_available():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@unittest.skipUnless(_ipv6_loopback_available(), "no IPv6 loopback")
class TcpServerIPv6Tests(_ServerTestBase):
    def test_listen_on_ipv6_loopback(self):
        self.start(srv.SocketmapServer(("::1", 0), StaticPolicy({"ex.de": "OK dane-only"}), "dane"))
        self.assertEqual(self.server.address_family, socket.AF_INET6)
        with socket.create_connection(("::1", self.server.server_address[1]), timeout=5) as sock:
            self.assertEqual(_ask(sock, "dane ex.de"), "OK dane-only")


class CliTests(unittest.TestCase):
    def test_defaults(self):
        args = srv.parse_args([])
        self.assertEqual((args.listen, args.port, args.mapname, args.socket),
                         ("127.0.0.1", 8462, "dane", None))
        self.assertEqual(args.max_connections, srv.DEFAULT_MAX_CONNECTIONS)

    def test_socket_option(self):
        self.assertEqual(srv.parse_args(["--socket", "/tmp/x.sock"]).socket, "/tmp/x.sock")

    def test_non_loopback_listen_is_refused(self):
        for addr in ("0.0.0.0", "192.0.2.10", "::", "mail.example.org"):
            with self.assertRaises(SystemExit, msg=addr):
                srv.parse_args(["--listen", addr])

    def test_non_loopback_listen_with_override(self):
        self.assertEqual(srv.parse_args(["--listen", "192.0.2.10", "--allow-remote"]).listen,
                         "192.0.2.10")

    def test_loopback_variants(self):
        for addr in ("127.0.0.1", "127.0.0.3", "::1"):
            self.assertEqual(srv.parse_args(["--listen", addr]).listen, addr)

    def test_invalid_limits(self):
        for argv in (["--max-connections", "0"], ["--lookup-budget", "0"]):
            with self.assertRaises(SystemExit):
                srv.parse_args(argv)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            srv.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
