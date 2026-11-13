# Changelog

## 0.2.0 - 2026-11-13

- FreeBSD is the primary platform now. CI builds the port from the current tree (portlint, stage, stage-qa, check-plist, package), installs the package, starts it via service(8) and queries it.
- `--listen` accepts IPv6 addresses (e.g. `::1`).
- README and pkg-message describe the base system `local_unbound` as default resolver.
- rc.d fixes found on a live jail (already part of the 0.1.0 tag): `postfix_dane_policy_args` instead of `_flags`, pidfile directory, no `-u` for daemon(8).

## 0.1.0 - 2026-11-13

- First release.
- Socketmap service answering `dane-only` for next-hop domains with DNSSEC-validated MX and TLSA records, `NOTFOUND` otherwise and `TEMP` on DNS failures.
- In-memory TTL cache, syslog logging, FreeBSD rc.d script, man page and FreeBSD port skeleton.
