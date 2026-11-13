import threading
import time
import unittest

from postfix_dane_policy import policy as dp


class FakeBackend:
    """Maps (name, rdtype) -> DnsAnswer; unknown names are NXDOMAIN."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def query(self, name, rdtype, lifetime=None):
        self.calls.append((name, rdtype))
        return self.answers.get((name, rdtype), dp.DnsAnswer("nxdomain"))


def mx(*hosts, secure=True, ttl=3600):
    return dp.DnsAnswer("ok", records=[(10 * (i + 1), h) for i, h in enumerate(hosts)],
                        secure=secure, ttl=ttl)


def tlsa(secure=True, ttl=1800, records=((3, 1, 1, 32),)):
    return dp.DnsAnswer("ok", records=list(records), secure=secure, ttl=ttl)


def addr(canonical, secure=True):
    return dp.DnsAnswer("ok", records=["192.0.2.1"], secure=secure, ttl=300, canonical=canonical)


class DecideTests(unittest.TestCase):
    def test_secure_mx_with_secure_tlsa_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(ttl=900)})
        result, ttl, _ = dp.decide("ex.de", b)
        self.assertEqual(result, dp.RESULT_DANE)
        self.assertEqual(ttl, 900)

    def test_insecure_mx_is_none_even_with_tlsa(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de", secure=False),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)

    def test_insecure_tlsa_is_none(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(secure=False)})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)

    def test_secure_mx_without_tlsa_is_none(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): dp.DnsAnswer("nodata", secure=True)})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)

    def test_mixed_mx_set_with_one_tlsa_host_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de", "mx2.ex.de"),
                         ("_25._tcp.mx2.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)

    def test_mx_servfail_is_temp(self):
        b = FakeBackend({("ex.de", "MX"): dp.DnsAnswer("fail", records=["SERVFAIL"])})
        result, ttl, reason = dp.decide("ex.de", b)
        self.assertEqual(result, dp.RESULT_TEMP)
        self.assertEqual(ttl, 0)
        self.assertIn("SERVFAIL", reason)

    def test_tlsa_servfail_without_other_tlsa_is_temp(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): dp.DnsAnswer("fail")})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_TEMP)

    def test_tlsa_servfail_but_other_host_secure_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de", "mx2.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): dp.DnsAnswer("fail"),
                         ("_25._tcp.mx2.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)

    def test_nxdomain_is_none(self):
        self.assertEqual(dp.decide("nope.de", FakeBackend({}))[0], dp.RESULT_NONE)

    def test_null_mx_is_none(self):
        b = FakeBackend({("ex.de", "MX"): dp.DnsAnswer("ok", records=[(0, "")], secure=True, ttl=60)})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)

    def test_no_mx_uses_domain_itself(self):
        b = FakeBackend({("ex.de", "MX"): dp.DnsAnswer("nodata", secure=True),
                         ("_25._tcp.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)
        self.assertIn(("_25._tcp.ex.de", "TLSA"), b.calls)

    def test_no_mx_insecure_is_none(self):
        b = FakeBackend({("ex.de", "MX"): dp.DnsAnswer("nodata", secure=False),
                         ("_25._tcp.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)

    def test_ttl_is_clamped(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de", ttl=10),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(ttl=5)})
        self.assertEqual(dp.decide("ex.de", b)[1], dp.POSITIVE_TTL_MIN)
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de", ttl=86400),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(ttl=86400)})
        self.assertEqual(dp.decide("ex.de", b)[1], dp.POSITIVE_TTL_MAX)


class TlsaUsabilityTests(unittest.TestCase):
    """dane-only with only unusable TLSA makes Postfix refuse the host (postconf(5))."""

    def test_usable_records(self):
        for rec in [(3, 1, 1, 32), (3, 0, 1, 32), (2, 1, 1, 32), (3, 1, 2, 64),
                    (2, 0, 0, 900), (3, 1, 0, 91)]:
            self.assertTrue(dp.tlsa_usable(rec), rec)

    def test_unusable_records(self):
        for rec in [(0, 1, 1, 32), (1, 1, 1, 32), (255, 1, 1, 32), (4, 1, 1, 32),
                    (3, 2, 1, 32), (3, 1, 3, 32), (3, 1, 1, 31), (3, 1, 2, 32),
                    (3, 1, 0, 0), "3 1 1 AABB", (3, 1), None]:
            self.assertFalse(dp.tlsa_usable(rec), rec)

    def test_only_unusable_tlsa_is_none(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(records=[(1, 1, 1, 32), (255, 1, 1, 32)])})
        result, _, reason = dp.decide("ex.de", b)
        self.assertEqual(result, dp.RESULT_NONE)
        self.assertEqual(reason, "no secure TLSA")

    def test_one_usable_record_is_enough(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa(records=[(0, 0, 1, 32), (3, 1, 1, 32)])})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)

    def test_unusable_at_cname_target_falls_back_to_original(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): addr("mx.provider.net"),
                         ("_25._tcp.mx.provider.net", "TLSA"): tlsa(records=[(1, 1, 1, 32)]),
                         ("_25._tcp.mx.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)


class CnameTests(unittest.TestCase):
    """RFC 7672 section 2.2.2: TLSA at the expanded name first, then the original."""

    def test_secure_cname_tlsa_only_at_target_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): addr("mx.provider.net"),
                         ("_25._tcp.mx.provider.net", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)
        idx_target = b.calls.index(("_25._tcp.mx.provider.net", "TLSA"))
        self.assertNotIn(("_25._tcp.mx.ex.de", "TLSA"), b.calls[:idx_target])

    def test_secure_cname_tlsa_only_at_original_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): addr("mx.provider.net"),
                         ("_25._tcp.mx.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)

    def test_insecure_cname_is_not_followed(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): addr("mx.provider.net", secure=False),
                         ("_25._tcp.mx.provider.net", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)
        self.assertNotIn(("_25._tcp.mx.provider.net", "TLSA"), b.calls)

    def test_cname_target_and_original_fail_is_temp(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): addr("mx.provider.net"),
                         ("_25._tcp.mx.provider.net", "TLSA"): dp.DnsAnswer("fail"),
                         ("_25._tcp.mx.ex.de", "TLSA"): dp.DnsAnswer("fail")})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_TEMP)

    def test_address_lookup_failure_without_tlsa_is_temp(self):
        # Without the address answer we cannot know whether a CNAME target has TLSA.
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): dp.DnsAnswer("fail")})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_TEMP)

    def test_address_lookup_failure_but_tlsa_at_original_is_dane(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx.ex.de"),
                         ("mx.ex.de", "A"): dp.DnsAnswer("fail"),
                         ("_25._tcp.mx.ex.de", "TLSA"): tlsa()})
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_DANE)


class LimitTests(unittest.TestCase):
    def test_only_first_mx_hosts_are_checked(self):
        hosts = ["mx%02d.ex.de" % i for i in range(15)]
        answers = {("ex.de", "MX"): mx(*hosts),
                   ("_25._tcp.mx14.ex.de", "TLSA"): tlsa()}
        b = FakeBackend(answers)
        self.assertEqual(dp.decide("ex.de", b)[0], dp.RESULT_NONE)
        self.assertNotIn(("_25._tcp.mx14.ex.de", "TLSA"), b.calls)
        self.assertEqual(sum(1 for c in b.calls if c[1] == "TLSA"), dp.MAX_MX_HOSTS)

    def test_duplicate_mx_hosts_are_checked_once(self):
        b = FakeBackend({("ex.de", "MX"): dp.DnsAnswer(
            "ok", records=[(10, "mx.ex.de"), (20, "mx.ex.de")], secure=True, ttl=60)})
        dp.decide("ex.de", b)
        self.assertEqual(b.calls.count(("_25._tcp.mx.ex.de", "TLSA")), 1)

    def test_exhausted_budget_is_temp(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        result, _, reason = dp.decide("ex.de", b, dp.Deadline(-1))
        self.assertEqual(result, dp.RESULT_TEMP)
        self.assertIn("budget", reason)
        self.assertEqual(b.calls, [])

    def test_lifetime_passed_to_backend(self):
        seen = []

        class B(FakeBackend):
            def query(self, name, rdtype, lifetime=None):
                seen.append(lifetime)
                return super().query(name, rdtype, lifetime)

        dp.decide("ex.de", B({}), dp.Deadline(7))
        self.assertTrue(seen and 0 < seen[0] <= 7)


class KeyTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(dp.normalize_key("Example.DE."), "example.de")
        self.assertEqual(dp.normalize_key(" sub.example.de "), "sub.example.de")
        self.assertEqual(dp.normalize_key("_dmarc-x.example.de"), "_dmarc-x.example.de")
        for bad in ["", ".de", ".example.de", "[1.2.3.4]", "[mx.example.de]:25",
                    "localhost", "a b.de", "example.de:587", "x\r\nInjected\tline.de",
                    "ex\x00ample.de", "a..de", "ex/ample.de", "ex%ample.de"]:
            self.assertIsNone(dp.normalize_key(bad), repr(bad))

    def test_length_limits(self):
        self.assertIsNone(dp.normalize_key("a" * 64 + ".de"))
        self.assertEqual(dp.normalize_key("a" * 63 + ".de"), "a" * 63 + ".de")
        self.assertIsNone(dp.normalize_key(".".join(["a" * 60] * 5) + ".de"))

    def test_idn_uses_uts46(self):
        self.assertEqual(dp.normalize_key("straße.de"), "xn--strae-oqa.de")
        self.assertEqual(dp.normalize_key("Bücher.example"), "xn--bcher-kva.example")

    def test_invalid_idn_is_none(self):
        self.assertIsNone(dp.normalize_key("☃́.de​"))


class PolicyTests(unittest.TestCase):
    def test_reply_strings(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        p = dp.Policy(b)
        self.assertEqual(p.lookup("ex.de"), "OK dane-only")
        self.assertEqual(p.lookup("other.de"), "NOTFOUND ")
        self.assertEqual(p.lookup(".ex.de"), "NOTFOUND ")
        bf = FakeBackend({("f.de", "MX"): dp.DnsAnswer("fail", records=["boom"])})
        self.assertTrue(dp.Policy(bf).lookup("f.de").startswith("TEMP "))

    def test_temp_reason_is_printable(self):
        reply = dp.response_for(dp.RESULT_TEMP, "bad\r\nthing\x00")
        self.assertEqual(reply, "TEMP bad??thing?")

    def test_cache_hit_avoids_dns(self):
        b = FakeBackend({("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        p = dp.Policy(b)
        p.lookup("ex.de")
        calls = len(b.calls)
        p.lookup("EX.de")
        self.assertEqual(len(b.calls), calls)

    def test_temp_is_not_cached(self):
        b = FakeBackend({("f.de", "MX"): dp.DnsAnswer("fail")})
        p = dp.Policy(b)
        p.lookup("f.de")
        p.lookup("f.de")
        self.assertEqual(b.calls.count(("f.de", "MX")), 2)

    def test_concurrent_lookups_are_coalesced(self):
        gate = threading.Event()

        class Slow(FakeBackend):
            def query(self, name, rdtype, lifetime=None):
                if rdtype == "MX":
                    gate.wait(5)
                return super().query(name, rdtype, lifetime)

        b = Slow({("ex.de", "MX"): mx("mx1.ex.de"),
                  ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        p = dp.Policy(b)
        replies = []
        threads = [threading.Thread(target=lambda: replies.append(p.lookup("ex.de")))
                   for _ in range(5)]
        for t in threads:
            t.start()
        time.sleep(0.2)
        gate.set()
        for t in threads:
            t.join(5)
        self.assertEqual(replies, ["OK dane-only"] * 5)
        self.assertEqual(b.calls.count(("ex.de", "MX")), 1)


class CacheTests(unittest.TestCase):
    def test_expiry(self):
        c = dp.PolicyCache()
        c.put("a.de", "OK dane-only", 10, now=100)
        self.assertEqual(c.get("a.de", now=105), "OK dane-only")
        self.assertIsNone(c.get("a.de", now=111))

    def test_lru_eviction(self):
        c = dp.PolicyCache(max_entries=3)
        for name in ("a.de", "b.de", "c.de"):
            c.put(name, "NOTFOUND ", 100, now=0)
        c.get("a.de", now=1)              # a is now most recently used
        c.put("d.de", "NOTFOUND ", 100, now=1)
        self.assertEqual(len(c), 3)
        self.assertIsNone(c.get("b.de", now=2))
        self.assertEqual(c.get("a.de", now=2), "NOTFOUND ")


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def test_validating_resolver_is_ok(self):
        b = FakeBackend({(".", "SOA"): dp.DnsAnswer("ok", records=["x"], secure=True)})
        h = dp.ResolverHealth(b, clock=self.clock)
        self.assertTrue(h.is_ok())

    def test_non_validating_resolver_makes_policy_temp(self):
        b = FakeBackend({(".", "SOA"): dp.DnsAnswer("ok", records=["x"], secure=False),
                         ("ex.de", "MX"): mx("mx1.ex.de"),
                         ("_25._tcp.mx1.ex.de", "TLSA"): tlsa()})
        p = dp.Policy(b, health=dp.ResolverHealth(b, clock=self.clock))
        self.assertEqual(p.lookup("ex.de"), dp.REPLY_RESOLVER_BROKEN)
        self.assertNotIn(("ex.de", "MX"), b.calls)
        # invalid keys are still answered without asking the resolver
        self.assertEqual(p.lookup(".ex.de"), "NOTFOUND ")

    def test_recheck_intervals(self):
        answers = {(".", "SOA"): dp.DnsAnswer("fail")}
        b = FakeBackend(answers)
        h = dp.ResolverHealth(b, interval_ok=600, interval_bad=30, clock=self.clock)
        self.assertFalse(h.is_ok())
        answers[(".", "SOA")] = dp.DnsAnswer("ok", records=["x"], secure=True)
        self.now = 10
        self.assertFalse(h.is_ok())        # within the bad interval, not rechecked
        self.now = 31
        self.assertTrue(h.is_ok())         # rechecked after 30 s
        answers[(".", "SOA")] = dp.DnsAnswer("fail")
        self.now = 300
        self.assertTrue(h.is_ok())         # ok state is kept for 600 s
        self.now = 700
        self.assertFalse(h.is_ok())


if __name__ == "__main__":
    unittest.main()
