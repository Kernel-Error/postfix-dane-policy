# Changelog

## 0.3.0 - 2026-11-13

Fixes from the security review of 0.2.0.

- MX host names that are DNSSEC-validated CNAMEs are expanded before the TLSA lookup, TLSA is tried at the target first and then at the original name (RFC 7672 section 2.2.2). Before, such domains wrongly got `NOTFOUND`. (#1)
- Unix socket support (`--socket`) and the rc.d script defaults to it, with a dedicated user `danepolicy` (UID/GID 801) instead of `nobody`. The socket directory is `danepolicy:postfix` mode 0750, the daemon(8) supervisor pidfile is owned by root. (#2)
- Limits: max concurrent connections (`--max-connections`, default 64), a started request must be complete within 10 s (no more slowloris), at most 10 MX hosts, total lookup budget (`--lookup-budget`, default 20 s), identical concurrent lookups are merged. Non-loopback `--listen` addresses are refused without `--allow-remote`. (#3)
- Lookup keys are converted to A-labels (IDNA 2008/UTS#46) and must be valid host names afterwards, everything else is `NOTFOUND`. Logs use repr() so keys can't inject log lines; TEMP reasons are printable ASCII only. (#4)
- Resolver self-test at startup and every 10 minutes: if the resolver doesn't set AD for the signed root zone, all lookups answer `TEMP`. dnspython >= 2.6.1 (CVE-2023-29483), new dependency idna. LRU cache, write errors handled, socket removed on SIGTERM. CI actions pinned to commit SHAs, no persisted credentials, and committed distinfo is checked against the real release tarball. (#5)

Upgrade notes: see README "Upgrading from 0.2.x". A TCP setup keeps working.

## 0.2.0 - 2026-11-13

- FreeBSD is the primary platform now. CI builds the port from the current tree (portlint, stage, stage-qa, check-plist, package), installs the package, starts it via service(8) and queries it.
- `--listen` accepts IPv6 addresses (e.g. `::1`).
- README and pkg-message describe the base system `local_unbound` as default resolver.
- rc.d fixes found on a live jail (already part of the 0.1.0 tag): `postfix_dane_policy_args` instead of `_flags`, pidfile directory, no `-u` for daemon(8).

## 0.1.0 - 2026-11-13

- First release.
- Socketmap service answering `dane-only` for next-hop domains with DNSSEC-validated MX and TLSA records, `NOTFOUND` otherwise and `TEMP` on DNS failures.
- In-memory TTL cache, syslog logging, FreeBSD rc.d script, man page and FreeBSD port skeleton.
