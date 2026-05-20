# cis-alpine-hardening

A POSIX-`sh` auditing and remediation toolkit that maps the
[**CIS Distribution-Independent Linux Benchmark v2.0.0**][cis] onto the
realities of Alpine Linux (musl + BusyBox + OpenRC).

The benchmark assumes systemd, glibc, GRUB, auditd, and PAM. Alpine ships
none of those by default. This repo translates the controls into Alpine-native
checks, names the deviations honestly in [`docs/ALPINE_DEVIATIONS.md`](docs/ALPINE_DEVIATIONS.md),
and produces an audit run that a security reviewer can map line-for-line back
to the CIS document.

It is written in POSIX `sh` so it runs on a vanilla Alpine image with nothing
but BusyBox `ash` — no `bash`, no `python`, no external dependencies.

[cis]: https://www.cisecurity.org/benchmark/distribution_independent_linux

---

## Why this exists

I built this while working on a contracted Linux hardening engagement for a
small-fleet customer running Alpine in production. The customer's compliance
auditor wanted to see CIS coverage. I wanted to ship something repeatable that
could be re-run as part of CI — and that someone other than me could read.

The version on GitHub is rewritten from scratch and contains no client
material. It is the methodology, not the deliverable.

## What it does

- **`audit.sh`** runs the checks. Every check prints `[PASS]`, `[FAIL]`,
  `[INFO]`, or `[SKIP]` with the CIS control ID and a one-line remediation
  hint. Exit code is `1` if anything failed — so CI can gate on it.
- **`remediate.sh --dry-run`** prints the diff of changes a safe subset of
  the CIS controls would apply. **`--apply`** actually writes them. Anything
  that risks locking you out (firewall rules, `PermitRootLogin no` on a
  single-admin host) is intentionally not in the remediation path; you do
  those by hand after reading the audit report.
- **`docs/`** documents the Alpine-specific deviations, a sample run, and a
  finding-report template.

See [`docs/SAMPLE_OUTPUT.md`](docs/SAMPLE_OUTPUT.md) for a real run on a
fresh Alpine 3.20 minirootfs.

## Coverage

| Section | CIS chapter | What's checked |
|---|---|---|
| `01-initial-setup.sh` | 1 | obsolete filesystem modules, sticky-bit on world-writable dirs, AIDE, secure boot (extlinux vs GRUB), `fs.suid_dumpable`, ASLR, MAC framework presence, warning banners |
| `02-services.sh` | 2 | inetd / legacy daemons, chrony time sync, X server / CUPS / DHCP / LDAP / NFS / FTP / HTTP / SMB / SNMP absence, postfix loopback-only |
| `03-network.sh` | 3 | full `net.ipv4.*` sysctl baseline, IPv6 hardening when enabled, uncommon protocol modules (dccp/sctp/rds/tipc), awall / nft / iptables ruleset presence |
| `04-logging.sh` | 4 | auditd if installed, rsyslog / syslog-ng / busybox-syslogd selection, `/var/log` permissions and world-readability |
| `05-access.sh` | 5 | crond + cron file modes, sshd full hardening (Protocol 2, MaxAuthTries, PermitRootLogin, ciphers/MACs/KEX), PAM if installed, password aging, default umask, su restriction |
| `06-maintenance.sh` | 6 | `/etc/{passwd,shadow,group,gshadow}` perms, world-writable / unowned / SUID inventory, password fields, legacy `+` entries, UID 0 sanity, root PATH, home directory ownership |

Not every CIS line item is implemented; the toolkit covers a representative
subset across all six chapters (roughly 70 controls). Extending it is a
matter of dropping another function into the relevant `checks/0X-*.sh` file
and using the existing helpers in `lib/common.sh`.

## Usage

```sh
# Clone and run
git clone https://github.com/fogazi42/cis-alpine-hardening.git
cd cis-alpine-hardening

# Audit all sections (run as root for accurate /etc/shadow checks)
doas ./audit.sh

# Audit only sections 1 and 5
doas ./audit.sh 1 5

# See what the safe remediation set would change
./remediate.sh --dry-run

# Actually apply the safe remediations
doas ./remediate.sh --apply
```

The audit script is read-only. The remediation script writes to:

- `/etc/sysctl.d/99-cis.conf`
- `/etc/profile.d/cis-umask.sh`
- `/etc/security/limits.conf` (append only)
- `/etc/ssh/sshd_config.d/99-cis-baseline.conf`

…and runs `chmod +t` on world-writable directories. Nothing else is touched.

## CI integration

The repository ships a GitHub Actions workflow at
[`.github/workflows/shellcheck.yml`](.github/workflows/shellcheck.yml) that
runs [`shellcheck`](https://www.shellcheck.net/) over every `.sh` file in
the repo. That's the contract: anything that lands on `main` is clean against
the same linter you'd run yourself.

## Limitations — read before you cite this in an interview

- **Coverage is representative, not complete.** The CIS document has roughly
  200 line items. This repo covers ~70. Extending the rest is mechanical;
  see `lib/common.sh` for the helper inventory.
- **No central reporting.** Output is per-host. If you need a fleet-wide
  view, pipe `audit.sh` output into a log shipper (rsyslog → SIEM) or wrap
  it in your existing config-management runner.
- **Some controls are inherently INFO on Alpine.** SELinux, GRUB password,
  auditd, full PAM stack — these don't exist out of the box. The toolkit
  emits `[INFO]` rather than pretending they pass. See
  [`docs/ALPINE_DEVIATIONS.md`](docs/ALPINE_DEVIATIONS.md).
- **The remediation set is intentionally narrow.** Things that risk lockout
  (firewall rules, `PermitRootLogin no` without verified backup access) are
  left to the operator.

## License

MIT — see [`LICENSE`](LICENSE).

The CIS benchmark itself is published by the Center for Internet Security
under their own terms; this repo cites it for reference and does not
reproduce its text.

## About

Written by Bassel Abdelkader as a portable, auditable foundation for CIS
hardening work on Alpine fleets. Reach me at
[linkedin.com/in/bassel-abdelkader](https://www.linkedin.com/in/bassel-abdelkader/).
