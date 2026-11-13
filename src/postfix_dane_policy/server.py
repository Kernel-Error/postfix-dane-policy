"""Postfix socketmap protocol server and command line entry point."""

import argparse
import ipaddress
import logging
import logging.handlers
import os
import signal
import socket
import socketserver
import stat
import sys
import threading
import time

from . import __version__
from .policy import (DEFAULT_LOOKUP_BUDGET, DnsBackend, Policy, ResolverHealth, log)

MAX_NETSTRING = 10000
IDLE_TIMEOUT = 300.0      # wait for the first byte of the next request
REQUEST_TIMEOUT = 10.0    # a started request must be complete within this time
DEFAULT_MAX_CONNECTIONS = 64


def encode_netstring(text):
    data = text.encode("utf-8")
    return str(len(data)).encode("ascii") + b":" + data + b","


class SocketReader:
    """Buffered reader on a raw socket that enforces a deadline.

    Unlike io.BufferedReader.read(n), which may call recv() several times
    with the full socket timeout each, the remaining time is recomputed
    before every recv(), so a client dripping single bytes can't stretch a
    request beyond its deadline.
    """

    def __init__(self, sock, idle_timeout):
        self.sock = sock
        self.idle_timeout = idle_timeout
        self.deadline = None
        self._buf = b""

    def read(self, size):
        while len(self._buf) < size:
            if self.deadline is None:
                self.sock.settimeout(self.idle_timeout)
            else:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("request timeout")
                self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self._buf += chunk
        data, self._buf = self._buf[:size], self._buf[size:]
        return data


def read_netstring(rfile, first=b""):
    """Read one netstring from anything with read(n); bytes, or None on clean EOF."""
    length = b""
    while True:
        ch = first if first else rfile.read(1)
        first = b""
        if not ch:
            if length:
                raise ValueError("truncated netstring length")
            return None
        if ch == b":":
            break
        if not ch.isdigit() or len(length) > 5:
            raise ValueError("invalid netstring length")
        length += ch
    if not length:
        raise ValueError("empty netstring length")
    size = int(length)
    if size > MAX_NETSTRING:
        raise ValueError("netstring too long")
    data = rfile.read(size)
    if len(data) != size:
        raise ValueError("truncated netstring")
    if rfile.read(1) != b",":
        raise ValueError("truncated netstring")
    return data


def handle_request(policy, mapname, data):
    """Answer one socketmap request ("<mapname> <key>")."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "PERM invalid encoding"
    name, _, key = text.partition(" ")
    if name != mapname:
        return "PERM unknown map"
    try:
        return policy.lookup(key)
    except Exception:  # never crash the connection on one bad lookup
        log.exception("lookup failed for %r", key)
        return "TEMP internal error"


class SocketmapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        reader = SocketReader(sock, self.server.idle_timeout)
        while True:
            try:
                reader.deadline = None
                first = reader.read(1)
                if not first:
                    return
                reader.deadline = time.monotonic() + self.server.request_timeout
                data = read_netstring(reader, first=first)
            except (ValueError, OSError) as exc:
                log.warning("protocol error from %r: %s", self.client_address, exc)
                return
            if data is None:
                return
            reply = handle_request(self.server.policy, self.server.mapname, data)
            try:
                sock.settimeout(self.server.request_timeout)
                sock.sendall(encode_netstring(reply))
            except OSError:
                return


class _SocketmapServerMixin:
    daemon_threads = True

    def _init_socketmap(self, policy, mapname, max_connections):
        self.policy = policy
        self.mapname = mapname
        self.max_connections = max_connections
        self.idle_timeout = IDLE_TIMEOUT
        self.request_timeout = REQUEST_TIMEOUT
        self._active = 0
        self._active_lock = threading.Lock()

    def process_request(self, request, client_address):
        with self._active_lock:
            refuse = self._active >= self.max_connections
            if not refuse:
                self._active += 1
        if refuse:
            log.warning("connection limit (%d) reached, refusing connection", self.max_connections)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._active_lock:
                self._active -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active -= 1


class SocketmapServer(_SocketmapServerMixin, socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, address, policy, mapname, max_connections=DEFAULT_MAX_CONNECTIONS):
        # IPv6 literal (e.g. "::1") -> AF_INET6, everything else stays AF_INET
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self._init_socketmap(policy, mapname, max_connections)
        super().__init__(address, SocketmapHandler)


def _socket_in_use(path):
    """True if something accepts connections on the unix socket path."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect(path)
        return True
    except OSError:
        return False
    finally:
        probe.close()


class UnixSocketmapServer(_SocketmapServerMixin, socketserver.ThreadingUnixStreamServer):
    def __init__(self, path, policy, mapname, max_connections=DEFAULT_MAX_CONNECTIONS):
        self._init_socketmap(policy, mapname, max_connections)
        self.socket_path = path
        self._socket_id = None
        if os.path.lexists(path):
            if not stat.S_ISSOCK(os.lstat(path).st_mode):
                raise RuntimeError("%s exists and is not a socket" % path)
            if _socket_in_use(path):
                raise RuntimeError("%s is in use by another process" % path)
            os.unlink(path)  # stale socket of a previous run
        super().__init__(path, SocketmapHandler)
        # Access is controlled by the permissions of the containing directory.
        os.chmod(path, 0o666)
        st = os.lstat(path)
        self._socket_id = (st.st_dev, st.st_ino)

    def server_close(self):
        super().server_close()
        # only remove the socket if it is still ours (not replaced meanwhile)
        try:
            st = os.lstat(self.socket_path)
            if self._socket_id == (st.st_dev, st.st_ino):
                os.unlink(self.socket_path)
        except OSError:
            pass


def is_loopback(address):
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _syslog_address():
    for path in ("/var/run/log", "/dev/log"):
        if os.path.exists(path):
            return path
    return ("localhost", 514)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="postfix-dane-policy",
        description="DANE-aware TLS policy socketmap service for Postfix")
    parser.add_argument("--socket", metavar="PATH",
                        help="listen on this unix socket instead of TCP (recommended)")
    parser.add_argument("--listen", default="127.0.0.1",
                        help="TCP listen address, IPv4 or IPv6 loopback (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8462, help="TCP listen port (default 8462)")
    parser.add_argument("--allow-remote", action="store_true",
                        help="allow a non-loopback --listen address (not recommended)")
    parser.add_argument("--dns", default="127.0.0.1",
                        help="validating DNS resolver address (default 127.0.0.1)")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout per query in seconds")
    parser.add_argument("--lookup-budget", type=float, default=DEFAULT_LOOKUP_BUDGET,
                        help="total time budget per policy lookup in seconds (default 20)")
    parser.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS,
                        help="maximum concurrent client connections (default 64)")
    parser.add_argument("--mapname", default="dane", help="socketmap name (default dane)")
    parser.add_argument("--log", choices=("syslog", "stderr"), default="syslog")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def parse_args(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.socket and not args.allow_remote and not is_loopback(args.listen):
        parser.error("--listen %s is not a loopback address; use --socket, a loopback "
                     "address or --allow-remote" % args.listen)
    if args.max_connections < 1:
        parser.error("--max-connections must be at least 1")
    if args.lookup_budget <= 0:
        parser.error("--lookup-budget must be positive")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.log == "stderr":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s postfix-dane-policy: %(message)s"))
    else:
        handler = logging.handlers.SysLogHandler(
            address=_syslog_address(), facility=logging.handlers.SysLogHandler.LOG_MAIL)
        handler.setFormatter(logging.Formatter("postfix-dane-policy[%d]: %%(message)s" % os.getpid()))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    backend = DnsBackend(args.dns, args.dns_port, args.timeout)
    health = ResolverHealth(backend)
    health.check()
    policy = Policy(backend, health=health, budget=args.lookup_budget)

    if args.socket:
        server = UnixSocketmapServer(args.socket, policy, args.mapname, args.max_connections)
        where = "unix:%s" % args.socket
    else:
        server = SocketmapServer((args.listen, args.port), policy, args.mapname,
                                 args.max_connections)
        where = "%s:%d" % (args.listen, args.port)
    log.info("version %s listening on %s map=%s dns=%s", __version__, where, args.mapname, args.dns)
    # SIGTERM (service stop, daemon(8)) -> leave serve_forever cleanly so the
    # unix socket is removed in server_close().
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
        log.info("stopped")
    return 0
