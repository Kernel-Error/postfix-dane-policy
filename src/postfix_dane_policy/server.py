"""Postfix socketmap protocol server and command line entry point."""

import argparse
import logging
import logging.handlers
import os
import socketserver
import sys

from . import __version__
from .policy import DnsBackend, Policy, log

MAX_NETSTRING = 10000


def encode_netstring(text):
    data = text.encode("utf-8")
    return str(len(data)).encode("ascii") + b":" + data + b","


def read_netstring(rfile):
    """Read one netstring; return bytes, or None on clean EOF."""
    length = b""
    while True:
        ch = rfile.read(1)
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
    if len(data) != size or rfile.read(1) != b",":
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
        return "PERM unknown map %s" % name[:50]
    try:
        return policy.lookup(key)
    except Exception as exc:  # never crash the connection on one bad lookup
        log.exception("lookup failed for %r", key)
        return "TEMP internal error: %s" % str(exc)[:100]


class SocketmapHandler(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        while True:
            try:
                data = read_netstring(self.rfile)
            except (ValueError, OSError) as exc:
                log.warning("protocol error from %s: %s", self.client_address, exc)
                return
            if data is None:
                return
            reply = handle_request(self.server.policy, self.server.mapname, data)
            self.wfile.write(encode_netstring(reply))
            self.wfile.flush()


class SocketmapServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, policy, mapname):
        super().__init__(address, SocketmapHandler)
        self.policy = policy
        self.mapname = mapname


def _syslog_address():
    for path in ("/var/run/log", "/dev/log"):
        if os.path.exists(path):
            return path
    return ("localhost", 514)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="postfix-dane-policy",
        description="DANE-aware TLS policy socketmap service for Postfix")
    parser.add_argument("--listen", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8462, help="listen port (default 8462)")
    parser.add_argument("--dns", default="127.0.0.1",
                        help="validating DNS resolver address (default 127.0.0.1)")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds")
    parser.add_argument("--mapname", default="dane", help="socketmap name (default dane)")
    parser.add_argument("--log", choices=("syslog", "stderr"), default="syslog")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.log == "stderr":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s postfix-dane-policy: %(message)s"))
    else:
        handler = logging.handlers.SysLogHandler(
            address=_syslog_address(), facility=logging.handlers.SysLogHandler.LOG_MAIL)
        handler.setFormatter(logging.Formatter("postfix-dane-policy[%d]: %%(message)s" % os.getpid()))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    policy = Policy(DnsBackend(args.dns, args.dns_port, args.timeout))
    server = SocketmapServer((args.listen, args.port), policy, args.mapname)
    log.info("version %s listening on %s:%d map=%s dns=%s",
             __version__, args.listen, args.port, args.mapname, args.dns)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
