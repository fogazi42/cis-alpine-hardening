# Alpine Linux deviations from the CIS Distribution-Independent Linux Benchmark v2.0.0

The CIS benchmark is written for a "generic" Linux that — in practice — assumes
glibc, systemd, GRUB, syslog, PAM, and auditd. Alpine ships none of those by
default. The toolkit reflects this honestly: each affected control either has a
mapped Alpine equivalent, or is emitted as `[INFO]` / `[SKIP]` with a note.

The table below is the short version. Read it before you cite this repo in an
interview — recruiters who actually run Alpine in production will ask.

| CIS area | Generic Linux assumption | Alpine reality | How this toolkit handles it |
|---|---|---|---|
| 1.1 Filesystem | glibc + util-linux `mount`, full module set | musl + util-linux-misc; many obsolete fs modules absent from the kernel image | `check_module_disabled` accepts "module not present" as a pass |
| 1.4 Secure boot | GRUB2 with `grub-mkpasswd-pbkdf2` | typically extlinux / syslinux; no GRUB password concept | detects loader, runs GRUB checks only when GRUB is present; otherwise emits an INFO pointing here |
| 1.5 Process hardening | `prelink` is RHEL-default | not packaged | `check_pkg_absent prelink` → trivially passes |
| 1.6 Mandatory Access Control | SELinux (RHEL) or AppArmor (Ubuntu) shipped | neither shipped; AppArmor available via `apk add apparmor` + custom kernel boot params | emits INFO when no MAC framework is installed; passes if AppArmor is installed AND loaded |
| 2.1 inetd services | xinetd / inetd often present | not packaged by default | one collapsed `check_pkg_absent xinetd` |
| 2.2.1 Time sync | chrony preferred on RHEL/Ubuntu | chrony, openntpd, or busybox-ntpd | toolkit prefers chrony, accepts openntpd, INFO for busybox-ntpd |
| 3.5 Firewall | iptables + iptables-services | `awall` (Alpine's iptables wrapper), or `nft`, or raw iptables | detects whichever is present; checks the corresponding ruleset |
| 4.1 auditd | RHEL default; auditd + auditctl + auditd.conf | audit ships in `testing/` repo; musl support has historically been spotty | emits INFO when not installed and points users at busybox-syslogd forwarding as an alternative |
| 4.2 System logger | rsyslog default on RHEL/Ubuntu | rsyslog optional; default is busybox-syslogd | toolkit checks rsyslog first, falls back to syslog-ng, then INFO for busybox-syslogd |
| 5.3 PAM | linux-pam universally present | not installed unless explicitly added | INFO when `/etc/pam.d` is missing; pwquality / faillock checks only run when PAM is present |

## When to use this toolkit, when not

**Use it when:**
- Your Alpine host is a long-running fleet member (not a 30-second container).
- You can install `audit`, `apparmor`, or `linux-pam` if the benchmark line items require it.
- You want a starting baseline that can be extended into a fuller policy.

**Don't use it as-is for:**
- Single-process container images. Most CIS controls don't apply — instead use
  CIS Docker / Kubernetes benchmarks.
- Hosts you don't own. The remediation script writes to `/etc/sysctl.d/`,
  `/etc/profile.d/`, and `/etc/security/limits.conf`. Always review the dry-run
  diff first.

## Why we cite v2.0.0 specifically

The CIS Distribution-Independent Linux Benchmark released v2.0.0 on 2019-07-16.
Subsequent point releases adjust IPv6 wording and a handful of audit rules but
do not restructure the document. The control IDs used in this repo (e.g.
`1.1.21`, `5.2.13`) are stable across the 2.x line.
