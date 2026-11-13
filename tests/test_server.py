import io
import socket
import threading
import unittest

from postfix_dane_policy import policy as dp
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
        self.assertTrue(srv.handle_request(self.policy, "dane", b"other ex.de").startswith("PERM"))

    def test_bad_encoding(self):
        self.assertTrue(srv.handle_request(self.policy, "dane", b"\xff\xfe").startswith("PERM"))

    def test_exception_becomes_temp(self):
        self.assertTrue(srv.handle_request(self.policy, "dane", b"dane boom.de").startswith("TEMP"))


class TcpServerTests(unittest.TestCase):
    """End-to-end over a real socket, like Postfix talks to the service."""

    def setUp(self):
        self.server = srv.SocketmapServer(("127.0.0.1", 0), StaticPolicy({"ex.de": "OK dane-only"}),
                                          "dane")
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _ask(self, sock, payload):
        sock.sendall(srv.encode_netstring(payload))
        return srv.read_netstring(sock.makefile("rb")).decode()

    def test_persistent_connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            self.assertEqual(self._ask(sock, "dane ex.de"), "OK dane-only")
            self.assertEqual(self._ask(sock, "dane other.de"), "NOTFOUND ")

    def test_garbage_closes_connection(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(b"garbage")
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(100), b"")


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
class TcpServerIPv6Tests(unittest.TestCase):
    def test_listen_on_ipv6_loopback(self):
        server = srv.SocketmapServer(("::1", 0), StaticPolicy({"ex.de": "OK dane-only"}), "dane")
        self.assertEqual(server.address_family, socket.AF_INET6)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("::1", server.server_address[1]), timeout=5) as sock:
                sock.sendall(srv.encode_netstring("dane ex.de"))
                reply = srv.read_netstring(sock.makefile("rb")).decode()
            self.assertEqual(reply, "OK dane-only")
        finally:
            server.shutdown()
            server.server_close()


class CliTests(unittest.TestCase):
    def test_parser_defaults(self):
        args = srv.build_parser().parse_args([])
        self.assertEqual((args.listen, args.port, args.mapname), ("127.0.0.1", 8462, "dane"))

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            srv.build_parser().parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
