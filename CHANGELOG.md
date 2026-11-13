# Changelog

## 0.1.0 - 2026-11-13

- First release.
- Socketmap service answering `dane-only` for next-hop domains with DNSSEC-validated MX and TLSA records, `NOTFOUND` otherwise and `TEMP` on DNS failures.
- In-memory TTL cache, syslog logging, FreeBSD rc.d script, man page and FreeBSD port skeleton.
