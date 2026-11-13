"""Policy decision: does a next-hop domain have usable DANE?

For a next-hop domain whose MX RRset is DNSSEC-validated and where at
least one MX host publishes a DNSSEC-validated TLSA RRset for port 25,
the answer is "dane-only". Otherwise the answer is NOTFOUND, so that the
next Postfix policy map (e.g. MTA-STS) or the global
smtp_tls_security_level applies. DNS failures (SERVFAIL, bogus DNSSEC,
timeouts) yield TEMP, so Postfix defers delivery instead of downgrading.
"""

import logging
import threading
import time

import dns.exception
import dns.flags
import dns.resolver

RESULT_DANE = "dane"
RESULT_NONE = "none"
RESULT_TEMP = "temp"

POSITIVE_TTL_MIN = 60
POSITIVE_TTL_MAX = 3600
NEGATIVE_TTL = 300

log = logging.getLogger("postfix-dane-policy")


class DnsAnswer:
    """Result of a single DNS lookup, independent of the DNS library."""

    def __init__(self, status, records=(), secure=False, ttl=0):
        # status: "ok", "nxdomain", "nodata", "fail"
        self.status = status
        self.records = list(records)
        self.secure = secure
        self.ttl = ttl


class DnsBackend:
    """DNS lookups against one validating resolver, reporting the AD flag.

    The resolver must perform DNSSEC validation (e.g. a local Unbound);
    this service trusts its AD bit and does not validate on its own.
    """

    def __init__(self, server, port=53, timeout=5.0):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [server]
        self.resolver.port = port
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        self.resolver.use_edns(0, dns.flags.DO, 1232)
        self.resolver.flags = dns.flags.RD | dns.flags.AD
        self.resolver.cache = None

    def query(self, name, rdtype):
        try:
            answer = self.resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except dns.exception.DNSException as exc:
            return DnsAnswer("fail", records=[str(exc)])
        secure = bool(answer.response.flags & dns.flags.AD)
        if answer.rrset is None:
            return DnsAnswer("nodata", secure=secure)
        if rdtype == "MX":
            records = [(r.preference, r.exchange.to_text(omit_final_dot=True).lower())
                       for r in answer.rrset]
        else:
            records = [r.to_text() for r in answer.rrset]
        return DnsAnswer("ok", records=records, secure=secure, ttl=answer.rrset.ttl)


def normalize_key(key):
    """Return a lookup domain, or None if the key is not a plain domain.

    Postfix also queries parent domains with a leading dot and bracketed
    next-hops ([host]:port); those are answered with NOTFOUND.
    """
    key = key.strip().lower().rstrip(".")
    if not key or key.startswith(".") or key.startswith("[") or ":" in key:
        return None
    if "." not in key or " " in key:
        return None
    return key


def decide(domain, backend):
    """Return (result, ttl, reason) for a normalized next-hop domain."""
    mx = backend.query(domain, "MX")
    if mx.status == "fail":
        return RESULT_TEMP, 0, "MX lookup failed: %s" % (mx.records[0] if mx.records else "?")
    if mx.status == "nxdomain":
        return RESULT_NONE, NEGATIVE_TTL, "domain does not exist"
    if not mx.secure:
        return RESULT_NONE, NEGATIVE_TTL, "MX not DNSSEC-validated"

    if mx.status == "nodata":
        hosts = [domain]
        ttls = []
    else:
        mx_records = sorted(mx.records)
        if len(mx_records) == 1 and mx_records[0][1] in ("", "."):
            return RESULT_NONE, NEGATIVE_TTL, "null MX"
        hosts = [host for _, host in mx_records if host not in ("", ".")]
        ttls = [mx.ttl]

    tlsa_hosts = []
    failed_hosts = []
    for host in hosts:
        tlsa = backend.query("_25._tcp." + host, "TLSA")
        if tlsa.status == "fail":
            failed_hosts.append(host)
        elif tlsa.status == "ok" and tlsa.secure and tlsa.records:
            tlsa_hosts.append(host)
            ttls.append(tlsa.ttl)

    if tlsa_hosts:
        ttl = max(POSITIVE_TTL_MIN, min([POSITIVE_TTL_MAX] + ttls))
        return RESULT_DANE, ttl, "secure TLSA on " + ",".join(tlsa_hosts)
    if failed_hosts:
        return RESULT_TEMP, 0, "TLSA lookup failed for " + ",".join(failed_hosts)
    return RESULT_NONE, NEGATIVE_TTL, "no secure TLSA"


class PolicyCache:
    """Small thread-safe TTL cache for socketmap replies."""

    def __init__(self, max_entries=10000):
        self._lock = threading.Lock()
        self._data = {}
        self._max = max_entries

    def get(self, domain, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._data.get(domain)
            if entry and entry[0] > now:
                return entry[1]
            self._data.pop(domain, None)
            return None

    def put(self, domain, value, ttl, now=None):
        if ttl <= 0:
            return
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._data) >= self._max:
                self._data = {k: v for k, v in self._data.items() if v[0] > now}
                if len(self._data) >= self._max:
                    self._data.clear()
            self._data[domain] = (now + ttl, value)


def response_for(result, reason):
    """Map a decision to a socketmap reply payload."""
    if result == RESULT_DANE:
        return "OK dane-only"
    if result == RESULT_TEMP:
        return "TEMP " + reason[:200]
    return "NOTFOUND "


class Policy:
    def __init__(self, backend, cache=None):
        self.backend = backend
        self.cache = cache or PolicyCache()

    def lookup(self, key):
        domain = normalize_key(key)
        if domain is None:
            return "NOTFOUND "
        cached = self.cache.get(domain)
        if cached is not None:
            return cached
        result, ttl, reason = decide(domain, self.backend)
        reply = response_for(result, reason)
        log.info("domain=%s result=%s reason=%s", domain, result, reason)
        self.cache.put(domain, reply, ttl)
        return reply
