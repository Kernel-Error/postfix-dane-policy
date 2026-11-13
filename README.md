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
| SERVFAIL, bogus DNSSEC, timeout | `TEMP` | delivery is deferred, never downgraded |
| key is a parent domain (`.example.com`) or a `[host]:port` next-hop | `NOTFOUND` | |

No MX record means the domain itself is checked as the implicit MX. Replies are cached
in memory for the record TTL (60 s to 1 h); negative answers are cached for 5 minutes,
TEMP is never cached.

With a mixed MX set (some hosts with TLSA, some without) the reply is still `dane-only`.
Postfix then delivers only to hosts it can authenticate via DANE and skips the others,
rather than falling back to unauthenticated TLS.

## Platform

FreeBSD is the primary platform: rc.d script, man page and a port are part of this
repository and the port is built, installed and started in CI on every push. The code
itself is plain Python and also runs elsewhere, but only FreeBSD is tested end to end.

## Requirements

- Python 3.10 or newer, [dnspython](https://www.dnspython.org/) 2.x
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
until it is part of the ports tree. With a ports checkout in `/usr/ports`:

```sh
cp -R freebsd/mail/py-postfix-dane-policy /usr/ports/mail/
cd /usr/ports/mail/py-postfix-dane-policy && make install clean
```

Other systems (not tested end to end):

```sh
pip install git+https://github.com/Kernel-Error/postfix-dane-policy
```

## Configuration

Enable and start the service. The defaults (`--listen 127.0.0.1 --port 8462 --dns 127.0.0.1`)
fit `local_unbound`:

```sh
sysrc postfix_dane_policy_enable=YES
service postfix_dane_policy start
```

Different addresses, e.g. in a jail with Unbound on 127.0.0.3 (IPv6 works too, `--listen ::1`):

```sh
sysrc postfix_dane_policy_args="--listen 127.0.0.3 --port 8462 --dns 127.0.0.3"
service postfix_dane_policy restart
```

Then in `main.cf` put it in front of the MTA-STS resolver (DANE takes precedence over
MTA-STS, see RFC 8461):

```
smtp_tls_security_level = verify
smtp_dns_support_level = dnssec
smtp_tls_policy_maps =
    socketmap:inet:127.0.0.1:8462:dane,
    socketmap:inet:127.0.0.1:8461:mta-sts
```

Options: `--listen`, `--port`, `--dns`, `--dns-port`, `--timeout`, `--mapname`
(default `dane`), `--log syslog|stderr`. See `postfix-dane-policy(8)`.

Quick check by hand:

```sh
printf '14:dane posteo.de,' | nc 127.0.0.1 8462; echo
# 12:OK dane-only,
```

## Things to know before you switch to `verify`

- Mail to servers without a valid CA certificate (self-signed, expired, wrong name) and
  to servers without STARTTLS gets deferred and eventually bounces. Check your logs
  first: `grep -E "(Untrusted|Anonymous) TLS connection" /var/log/maillog` and
  deliveries with `tls=...:none`.
- `verify` checks the certificate against the MX hostname. Without DNSSEC on the
  recipient's MX lookup the MX hostname itself can be spoofed. That is a limit of
  `verify`, MTA-STS and DANE close it.
- Set `delay_warning_time` so senders learn early that a message is stuck.

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
