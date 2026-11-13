import unittest

from postfix_dane_policy import policy as dp


class FakeBackend:
    """Maps (name, rdtype) -> DnsAnswer; unknown names are NXDOMAIN."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def query(self, name, rdtype):
        self.calls.append((name, rdtype))
        return self.answers.get((name, rdtype), dp.DnsAnswer("nxdomain"))


def mx(*hosts, secure=True, ttl=3600):
    return dp.DnsAnswer("ok", records=[(10 * (i + 1), h) for i, h in enumerate(hosts)],
                        secure=secure, ttl=ttl)


def tlsa(secure=True, ttl=1800):
    return dp.DnsAnswer("ok", records=["3 1 1 AABB"], secure=secure, ttl=ttl)


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


class KeyTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(dp.normalize_key("Example.DE."), "example.de")
        self.assertEqual(dp.normalize_key(" sub.example.de "), "sub.example.de")
        for bad in ["", ".de", ".example.de", "[1.2.3.4]", "[mx.example.de]:25",
                    "localhost", "a b.de", "example.de:587"]:
            self.assertIsNone(dp.normalize_key(bad), bad)


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

    def test_cache_expiry(self):
        c = dp.PolicyCache()
        c.put("a.de", "OK dane-only", 10, now=100)
        self.assertEqual(c.get("a.de", now=105), "OK dane-only")
        self.assertIsNone(c.get("a.de", now=111))

    def test_cache_is_bounded(self):
        c = dp.PolicyCache(max_entries=3)
        for i in range(10):
            c.put("d%d.de" % i, "NOTFOUND ", 100, now=0)
        self.assertLessEqual(len(c._data), 3)
        self.assertEqual(c.get("d9.de", now=1), "NOTFOUND ")


if __name__ == "__main__":
    unittest.main()
