# postfix-dane-policy

A small socketmap service for Postfix `smtp_tls_policy_maps` that detects DANE.
It lets you run an outbound policy of **"DANE if published, else MTA-STS, else a
CA-verified certificate, never plaintext"**, which Postfix can't express on its own.

## Why

Postfix has no security level that means "use DANE when the recipient publishes
TLSA records, otherwise require a verified certificate":

- `dane` falls back to `may` when no TLSA records exist. That includes the plaintext
  fallback after a failed handshake, so an active attacker can force a downgrade.
- `verify` and `secure` ignore TLSA records completely. Recipients that use DANE-EE
  with self-signed certificates become unreachable.

postfix-dane-policy answers the DANE question per destination. Everything else
stays with Postfix and an optional MTA-STS resolver.

## Behaviour

For a next-hop domain the service looks up the MX RRset and the `_25._tcp` TLSA RRset
of each MX host through a validating resolver and checks the AD bit.

| Situation | Reply | Effect in Postfix |
|---|---|---|
| MX DNSSEC-validated, at least one MX host has a DNSSEC-validated TLSA RRset | `OK dane-only` | DANE authentication required, no fallback |
| MX not DNSSEC-validated, no TLSA, null MX, domain does not exist | `NOTFOUND` | next map (MTA-STS) or global level |
| SERVFAIL, bogus DNSSEC, timeout, lookup budget exceeded | `TEMP` | delivery is deferred, never downgraded |
| resolver does not validate DNSSEC (self-test failed) | `TEMP` | delivery is deferred until the resolver validates again |
| key is a parent domain (`.example.com`), a `[host]:port` next-hop or not a valid domain name | `NOTFOUND` | |

Details:

- **CNAME MX hosts** are handled like Postfix does it (RFC 7672 sections 2.2.2/2.2.3): if the MX
  host name is a DNSSEC-validated alias, TLSA is looked up at the expanded name first, then at the
  original name. The first secure TLSA RRset decides, a lookup failure stops (TEMP).
- **No MX record** means the domain itself is checked as the implicit MX.
- **Only usable TLSA counts:** DANE-TA(2)/DANE-EE(3), selector 0/1, matching type 0/1/2 with the
  right digest length (RFC 7672 section 3.1). A host that publishes only unusable records
  (e.g. PKIX-TA/PKIX-EE usages 0/1) is treated as having no TLSA, because with `dane-only`
  Postfix would refuse it entirely. RFC 7672 would fall back to unauthenticated `encrypt`
  there; this service lets MTA-STS or `verify` decide instead, which is stricter.
- **Mixed MX sets** (some hosts with TLSA, some without) still get `dane-only`. Postfix then
  delivers only to hosts it can authenticate via DANE and defers if none works. That is
  fail-closed on purpose: never a fallback to unauthenticated TLS.
- **IDN** keys are converted to A-labels with IDNA 2008 / UTS#46. Anything that is not a valid
  hostname afterwards (control characters, spaces, overlong labels) is answered `NOTFOUND` and
  never sent to DNS.
- **Limits:** at most 10 MX hosts are checked (by preference), one lookup gets 20 s in total
  (`--lookup-budget`), identical lookups that run at the same time are merged.
- **Cache:** replies are cached for the record TTL (60 s to 1 h), negative answers for 5 minutes,
  TEMP is never cached. LRU with 10 000 entries.
- **Resolver self-test:** at startup and every 10 minutes (every 30 s while failing) the service
  checks that the resolver sets the AD bit for the signed root zone. If it doesn't, every lookup
  answers `TEMP` and an error is logged, so a misconfigured `--dns` can't silently turn DANE off.

## Platform

FreeBSD is the primary platform: rc.d script, man page and a port are part of this
repository and the port is built, installed and started in CI on every push. The code
itself is plain Python and also runs elsewhere, but only FreeBSD is tested end to end.

## Requirements

- Python 3.10 or newer, [dnspython](https://www.dnspython.org/) 2.6.1 or newer, [idna](https://pypi.org/project/idna/)
- A **local, DNSSEC-validating resolver**. The service trusts the AD bit of that resolver
  and does not validate on its own. Don't point it at a remote resolver over an untrusted
  network.
- Postfix with `smtp_dns_support_level = dnssec` (Postfix needs the validating resolver too)

On FreeBSD the base system already has one: `local_unbound` validates DNSSEC and listens
on 127.0.0.1, which matches the defaults of this service.

```sh
sysrc local_unbound_enable=YES
service local_unbound start
drill -D posteo.de MX @127.0.0.1 | grep flags   # must show "ad"
```

If you run Unbound from ports (`dns/unbound`) or in a jail on another address, pass that
address with `--dns`.

## Installation on FreeBSD

The port lives in [`freebsd/mail/py-postfix-dane-policy`](freebsd/mail/py-postfix-dane-policy)
until it is part of the ports tree. It brings its own definition of the `danepolicy` user
(UID/GID 801) because that user isn't registered in the ports tree yet. With a ports checkout in
`/usr/ports`:

```sh
cp -R freebsd/mail/py-postfix-dane-policy /usr/ports/mail/
cd /usr/ports/mail/py-postfix-dane-policy && make install clean
```

Other systems (not tested end to end):

```sh
pip install git+https://github.com/Kernel-Error/postfix-dane-policy
```

## Configuration

The port creates the user `danepolicy`. Enable and start the service; the defaults listen on a
unix socket and use the resolver on 127.0.0.1, which fits `local_unbound`:

```sh
sysrc postfix_dane_policy_enable=YES
service postfix_dane_policy start
```

What you get:

- the service runs as `danepolicy` under daemon(8), the supervisor pidfile
  `/var/run/postfix_dane_policy.pid` belongs to root
- the socket `/var/run/postfix_dane_policy/policy.sock` lives in a directory owned by
  `danepolicy:postfix` with mode 0750, so only Postfix (and root) can talk to it

rc.conf knobs: `postfix_dane_policy_user` (default `danepolicy`), `postfix_dane_policy_group`
(the group Postfix runs as, default `postfix`) and `postfix_dane_policy_args`. Different resolver,
e.g. in a jail with Unbound on 127.0.0.3:

```sh
sysrc postfix_dane_policy_args="--socket /var/run/postfix_dane_policy/policy.sock --dns 127.0.0.3"
service postfix_dane_policy restart
```

Then in `main.cf` put it in front of the MTA-STS resolver (DANE takes precedence over
MTA-STS, see RFC 8461):

```
smtp_tls_security_level = verify
smtp_dns_support_level = dnssec
smtp_tls_policy_maps =
    socketmap:unix:/var/run/postfix_dane_policy/policy.sock:dane,
    socketmap:inet:127.0.0.1:8461:mta-sts
# verify and MTA-STS need a CA trust store (pkg install ca_root_nss)
smtp_tls_CAfile = /usr/local/share/certs/ca-root-nss.crt
# "TLS-Required: no" (RFC 8689) would let a sender switch off the whole policy
tls_required_enable = no
# verify, secure and dane-only use the *mandatory* protocol setting
smtp_tls_mandatory_protocols = >=TLSv1.2
```

Why the extra lines matter:

- `smtp_tls_CAfile`/`smtp_tls_CApath` are empty by default. Without a trust store `verify` and
  MTA-STS `secure` can't verify anything and every such delivery is deferred.
- `tls_required_enable` defaults to `yes` since Postfix 3.10. A message with the header
  `TLS-Required: no` then skips the policy lookup and is sent with level `may`, including the
  plaintext fallback. "Never plaintext" only holds with `tls_required_enable = no`.
- `smtp_tls_protocols` only applies to opportunistic TLS (`may`). For `verify`, `secure` and
  `dane-only` Postfix uses `smtp_tls_mandatory_protocols` (default `>=TLSv1`). Trade-off from
  postconf(5): "If you use dane or dane-only it is best not to disable TLSv1" -- a few DANE
  servers only speak TLS 1.0, `>=TLSv1.2` makes those unreachable.

TCP is still possible (`--listen 127.0.0.1 --port 8462`, or `::1`) but not recommended: any
local process could grab the port while the service restarts. Non-loopback addresses are
refused unless you pass `--allow-remote` -- don't, the protocol has no authentication.

Options: `--socket`, `--listen`, `--port`, `--allow-remote`, `--dns`, `--dns-port`, `--timeout`,
`--lookup-budget`, `--max-connections` (default 64), `--mapname` (default `dane`),
`--log syslog|stderr`. See `postfix-dane-policy(8)`.

Quick check by hand:

```sh
postmap -q posteo.de socketmap:unix:/var/run/postfix_dane_policy/policy.sock:dane
# dane-only
postmap -q gmail.com socketmap:unix:/var/run/postfix_dane_policy/policy.sock:dane
# (empty: NOTFOUND)
```

### Upgrading from 0.2.x

0.3.0 switches the defaults to the unix socket and the dedicated user. If you set
`postfix_dane_policy_args` to a TCP address it keeps working, but consider moving to the socket
and changing the first `smtp_tls_policy_maps` entry to `socketmap:unix:...`. Without the port,
create the user yourself: `pw groupadd danepolicy -g 801 && pw useradd danepolicy -u 801 -g danepolicy -d /nonexistent -s /usr/sbin/nologin`.

## Things to know before you switch to `verify`

- Mail to servers without a valid CA certificate (self-signed, expired, wrong name) and
  to servers without STARTTLS gets deferred and eventually bounces. As a first pass look
  at your outbound history: `grep "postfix/smtp\[" /var/log/maillog | grep -E
  "(Untrusted|Anonymous) TLS connection|tls=[a-z]*:none"`. That's only a pre-selection:
  "Trusted" connections can still fail the hostname check of `verify`. The real test is a
  probe with the new settings: `sendmail -bv someone@example.org` and look for
  `tls=verify`/`tls=!verify` in the log.
- `verify` checks the certificate against the MX hostname. Without DNSSEC on the
  recipient's MX lookup the MX hostname itself can be spoofed. That is a limit of
  `verify`, MTA-STS and DANE close it.
- Set `delay_warning_time` so senders learn early that a message is stuck.
- The service is fail-closed: DNS trouble, a non-validating resolver or a stopped service lead
  to deferred mail, never to plaintext. Watch the queue after changes.

## Related projects

- [postfix-mta-sts-resolver](https://github.com/Snawoot/postfix-mta-sts-resolver): MTA-STS
  only, by design no DANE. Works well as the second map behind this one.
- [postfix-tlspol](https://github.com/Zuplu/postfix-tlspol): DANE + MTA-STS in one Go
  daemon. Returns `dane` instead of `dane-only` for mixed MX sets, Linux binaries only.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

CI runs the unit tests on Linux (Python 3.10 to 3.14) and, on FreeBSD, builds the port
from the current tree (`portlint`, `make stage`, `check-plist`, `package`), installs the
package, starts it via `service` and queries it.

## License

MIT, see [LICENSE](LICENSE).
