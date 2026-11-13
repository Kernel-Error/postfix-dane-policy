"""Policy decision: does a next-hop domain have usable DANE?

For a next-hop domain whose MX RRset is DNSSEC-validated and where at
least one MX host publishes a DNSSEC-validated TLSA RRset for port 25,
the answer is "dane-only". Otherwise the answer is NOTFOUND, so that the
next Postfix policy map (e.g. MTA-STS) or the global
smtp_tls_security_level applies. DNS failures (SERVFAIL, bogus DNSSEC,
timeouts, exhausted lookup budget) and a resolver that does not validate
DNSSEC yield TEMP, so Postfix defers delivery instead of downgrading.
"""

import logging
import re
import threading
import time
from collections import OrderedDict

import dns.exception
import dns.flags
import dns.name
import dns.resolver

RESULT_DANE = "dane"
RESULT_NONE = "none"
RESULT_TEMP = "temp"

POSITIVE_TTL_MIN = 60
POSITIVE_TTL_MAX = 3600
NEGATIVE_TTL = 300

MAX_MX_HOSTS = 10
DEFAULT_LOOKUP_BUDGET = 20.0
SELFTEST_INTERVAL_OK = 600
SELFTEST_INTERVAL_BAD = 30

REPLY_RESOLVER_BROKEN = "TEMP resolver does not validate DNSSEC"

_LDH = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")

log = logging.getLogger("postfix-dane-policy")


class DnsAnswer:
    """Result of a single DNS lookup, independent of the DNS library."""

    def __init__(self, status, records=(), secure=False, ttl=0, canonical=None):
        # status: "ok", "nxdomain", "nodata", "fail"
        self.status = status
        self.records = list(records)
        self.secure = secure
        self.ttl = ttl
        self.canonical = canonical


class Deadline:
    """Overall time budget for one policy decision."""

    def __init__(self, budget):
        self.end = time.monotonic() + budget

    def remaining(self):
        return self.end - time.monotonic()


class DnsBackend:
    """DNS lookups against one validating resolver, reporting the AD flag.

    The resolver must perform DNSSEC validation (e.g. a local Unbound);
    this service trusts its AD bit and does not validate on its own.
    """

    def __init__(self, server, port=53, timeout=5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [server]
        self.resolver.port = port
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        self.resolver.use_edns(0, dns.flags.DO, 1232)
        self.resolver.flags = dns.flags.RD | dns.flags.AD
        self.resolver.cache = None

    def query(self, name, rdtype, lifetime=None):
        lifetime = self.timeout if lifetime is None else min(self.timeout, lifetime)
        if lifetime <= 0:
            return DnsAnswer("fail", records=["lookup budget exceeded"])
        try:
            answer = self.resolver.resolve(name, rdtype, raise_on_no_answer=False,
                                           lifetime=lifetime)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except dns.exception.DNSException as exc:
            return DnsAnswer("fail", records=[str(exc)])
        secure = bool(answer.response.flags & dns.flags.AD)
        canonical = answer.canonical_name.to_text(omit_final_dot=True).lower()
        if answer.rrset is None:
            return DnsAnswer("nodata", secure=secure, canonical=canonical)
        if rdtype == "MX":
            records = [(r.preference, r.exchange.to_text(omit_final_dot=True).lower())
                       for r in answer.rrset]
        elif rdtype == "TLSA":
            records = [(r.usage, r.selector, r.mtype, len(r.cert)) for r in answer.rrset]
        else:
            records = [r.to_text() for r in answer.rrset]
        return DnsAnswer("ok", records=records, secure=secure, ttl=answer.rrset.ttl,
                         canonical=canonical)


def normalize_key(key):
    """Return a lookup domain in A-label form, or None if the key is unusable.

    Postfix also queries parent domains with a leading dot and bracketed
    next-hops ([host]:port); those are answered with NOTFOUND. Non-ASCII
    keys are converted with IDNA 2008 / UTS#46, like Postfix does.
    """
    key = key.strip().rstrip(".")
    if not key or key[0] in ".[" or ":" in key:
        return None
    if not key.isascii():
        try:
            key = dns.name.from_unicode(
                key, idna_codec=dns.name.IDNA_2008_UTS_46).to_text(omit_final_dot=True)
        except Exception:  # invalid IDN or idna package missing
            return None
    key = key.lower()
    if len(key) > 253 or not _LDH.match(key):
        return None
    if any(len(label) > 63 for label in key.split(".")):
        return None
    return key


# RFC 7672 section 3.1: for SMTP only DANE-TA(2) and DANE-EE(3) are usable;
# selector Cert(0)/SPKI(1); matching type Full(0), SHA2-256(1), SHA2-512(2).
_DIGEST_LEN = {1: 32, 2: 64}


def tlsa_usable(record):
    """True if a TLSA record (usage, selector, mtype, data_len) is usable for SMTP."""
    try:
        usage, selector, mtype, data_len = record
    except (TypeError, ValueError):
        return False
    if usage not in (2, 3) or selector not in (0, 1) or mtype not in (0, 1, 2):
        return False
    if mtype == 0:
        return data_len > 0
    return data_len == _DIGEST_LEN[mtype]


def _tlsa_for_host(host, query):
    """Return (found, failed, ttl) for one MX host, following a secure CNAME.

    RFC 7672 section 2.2.2: if the MX host name is a DNSSEC-validated alias,
    TLSA records are looked up at the fully expanded name first and then at
    the original name. Only RRsets with at least one usable record count:
    with dane-only Postfix refuses hosts whose TLSA records are all unusable,
    so such hosts are better left to MTA-STS / verify.
    """
    candidates = [host]
    addr = query(host, "A")
    addr_failed = addr.status == "fail"
    if (addr.status in ("ok", "nodata") and addr.secure
            and addr.canonical and addr.canonical != host):
        candidates = [addr.canonical, host]

    failed = addr_failed
    for name in candidates:
        tlsa = query("_25._tcp." + name, "TLSA")
        if tlsa.status == "fail":
            failed = True
        elif (tlsa.status == "ok" and tlsa.secure
              and any(tlsa_usable(r) for r in tlsa.records)):
            return True, False, tlsa.ttl
    return False, failed, 0


def decide(domain, backend, deadline=None):
    """Return (result, ttl, reason) for a normalized next-hop domain."""
    deadline = deadline or Deadline(DEFAULT_LOOKUP_BUDGET)

    def query(name, rdtype):
        remaining = deadline.remaining()
        if remaining <= 0:
            return DnsAnswer("fail", records=["lookup budget exceeded"])
        return backend.query(name, rdtype, lifetime=remaining)

    mx = query(domain, "MX")
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
        hosts = []
        for _, host in mx_records:
            if host not in ("", ".") and host not in hosts:
                hosts.append(host)
        hosts = hosts[:MAX_MX_HOSTS]
        ttls = [mx.ttl]

    tlsa_hosts = []
    failed_hosts = []
    for host in hosts:
        found, failed, ttl = _tlsa_for_host(host, query)
        if found:
            tlsa_hosts.append(host)
            ttls.append(ttl)
        elif failed:
            failed_hosts.append(host)

    if tlsa_hosts:
        ttl = max(POSITIVE_TTL_MIN, min([POSITIVE_TTL_MAX] + ttls))
        return RESULT_DANE, ttl, "secure TLSA on " + ",".join(tlsa_hosts)
    if failed_hosts:
        return RESULT_TEMP, 0, "TLSA lookup failed for " + ",".join(failed_hosts)
    return RESULT_NONE, NEGATIVE_TTL, "no secure TLSA"


class PolicyCache:
    """Small thread-safe TTL cache with LRU eviction."""

    def __init__(self, max_entries=10000):
        self._lock = threading.Lock()
        self._data = OrderedDict()
        self._max = max_entries

    def get(self, domain, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._data.get(domain)
            if entry is None:
                return None
            if entry[0] <= now:
                del self._data[domain]
                return None
            self._data.move_to_end(domain)
            return entry[1]

    def put(self, domain, value, ttl, now=None):
        if ttl <= 0:
            return
        now = time.monotonic() if now is None else now
        with self._lock:
            self._data[domain] = (now + ttl, value)
            self._data.move_to_end(domain)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def __len__(self):
        return len(self._data)


class ResolverHealth:
    """Checks that the resolver validates DNSSEC (AD bit on the signed root)."""

    def __init__(self, backend, interval_ok=SELFTEST_INTERVAL_OK,
                 interval_bad=SELFTEST_INTERVAL_BAD, clock=time.monotonic):
        self.backend = backend
        self.interval_ok = interval_ok
        self.interval_bad = interval_bad
        self.clock = clock
        self._lock = threading.Lock()
        self._ok = None
        self._checked = None

    def check(self):
        answer = self.backend.query(".", "SOA")
        ok = answer.status == "ok" and answer.secure
        with self._lock:
            changed = ok != self._ok
            self._ok = ok
            self._checked = self.clock()
        if changed:
            if ok:
                log.info("resolver self-test passed: AD bit set for the root zone")
            else:
                log.error("resolver self-test FAILED (status=%r, AD=%r): resolver does not "
                          "validate DNSSEC, answering TEMP until it does",
                          answer.status, answer.secure)
        return ok

    def is_ok(self):
        with self._lock:
            ok, checked = self._ok, self._checked
        interval = self.interval_ok if ok else self.interval_bad
        if checked is None or self.clock() - checked >= interval:
            return self.check()
        return ok


def response_for(result, reason):
    """Map a decision to a socketmap reply payload."""
    if result == RESULT_DANE:
        return "OK dane-only"
    if result == RESULT_TEMP:
        return "TEMP " + _UNPRINTABLE.sub("?", reason)[:200]
    return "NOTFOUND "


class _Inflight:
    def __init__(self):
        self.event = threading.Event()
        self.reply = None


class Policy:
    def __init__(self, backend, cache=None, health=None, budget=DEFAULT_LOOKUP_BUDGET):
        self.backend = backend
        self.cache = cache or PolicyCache()
        self.health = health
        self.budget = budget
        self._lock = threading.Lock()
        self._inflight = {}

    def lookup(self, key):
        domain = normalize_key(key)
        if domain is None:
            return "NOTFOUND "
        if self.health is not None and not self.health.is_ok():
            return REPLY_RESOLVER_BROKEN
        cached = self.cache.get(domain)
        if cached is not None:
            return cached

        # Coalesce identical lookups that are already running.
        with self._lock:
            pending = self._inflight.get(domain)
            leader = pending is None
            if leader:
                pending = _Inflight()
                self._inflight[domain] = pending
        if not leader:
            if pending.event.wait(self.budget + 5) and pending.reply is not None:
                return pending.reply
            return "TEMP concurrent lookup did not finish"

        reply = "TEMP internal error"
        try:
            result, ttl, reason = decide(domain, self.backend, Deadline(self.budget))
            reply = response_for(result, reason)
            log.info("domain=%r result=%s reason=%r", domain, result, reason)
            self.cache.put(domain, reply, ttl)
            return reply
        finally:
            pending.reply = reply
            with self._lock:
                self._inflight.pop(domain, None)
            pending.event.set()
