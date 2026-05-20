# Sample audit run

The output below is from a fresh Alpine 3.20 minirootfs with `openssh` and
`chrony` added. It is reproduced here so reviewers can see what the toolkit
emits before running it themselves.

```
$ ./audit.sh
Alpine version detected: 3.20.3
Init system    : openrc
Firewall       : iptables
Logger         : busybox-syslogd

== 1 Initial Setup ==
  [PASS] cramfs: module not present in kernel image
  [PASS] freevxfs: module not present in kernel image
  [PASS] jffs2: module not present in kernel image
  [PASS] hfs: module not present in kernel image
  [PASS] hfsplus: module not present in kernel image
  [PASS] squashfs: module not present in kernel image
  [PASS] udf: module not present in kernel image
  [PASS] 1.1.21 no world-writable directories missing sticky bit
  [PASS] package autofs is not installed
  [FAIL] package aide is missing
         remediate: apk add aide
  [SKIP] 1.4 no GRUB/extlinux config found
  [FAIL] sysctl fs.suid_dumpable = 1 (expected 0)
         remediate: echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-cis.conf && sysctl --system
  [FAIL] 1.5.1 no 'hard core 0' rule in /etc/security/limits.conf
         remediate: echo '*    hard    core    0' >> /etc/security/limits.conf
  [PASS] sysctl kernel.randomize_va_space = 2
  [PASS] package prelink is not installed
  [INFO] 1.6 no MAC framework installed. Alpine does not ship SELinux; AppArmor is available via 'apk add apparmor'.
  [SKIP] 1.7 /etc/motd not present
  [PASS] mode on /etc/issue is 644
  [PASS] ownership on /etc/issue is root:root
  [PASS] 1.7 /etc/issue does not leak OS information
  [SKIP] 1.7 /etc/issue.net not present

== 2 Services ==
  [PASS] package xinetd is not installed
  [PASS] package netkit-rsh is not installed
  [PASS] package netkit-telnet is not installed
  [PASS] package talk is not installed
  [PASS] chronyd is enabled at default runlevel
  [PASS] 2.2.1.3 chrony has at least one upstream server/pool
  [PASS] package xorg-server is not installed
  [PASS] package avahi is not installed
  [PASS] package cups is not installed
  [PASS] package isc-dhcp-server is not installed
  [PASS] package openldap-servers is not installed
  [PASS] package nfs-utils is not installed
  [PASS] package bind is not installed
  [PASS] package vsftpd is not installed
  [PASS] package apache2 is not installed
  [PASS] package nginx is not installed
  [PASS] package dovecot is not installed
  [PASS] package samba is not installed
  [PASS] package squid is not installed
  [PASS] package net-snmp is not installed
  [PASS] 2.2.15 no postfix installed (acceptable on a non-mail host)
  [PASS] 2.2.16 rsyncd daemon is not enabled

== 3 Network Configuration ==
  [PASS] sysctl net.ipv4.ip_forward = 0
  [FAIL] sysctl net.ipv4.conf.all.send_redirects = 1 (expected 0)
         remediate: echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/99-cis.conf && sysctl --system
  [PASS] sysctl net.ipv4.conf.all.accept_source_route = 0
  [PASS] sysctl net.ipv4.conf.all.rp_filter = 1
  [PASS] sysctl net.ipv4.tcp_syncookies = 1
  [FAIL] 3.5 iptables INPUT default policy is not DROP
         remediate: iptables -P INPUT DROP   (after allowing loopback + established)
  [PASS] 3.6 no active wireless interfaces

== 4 Logging and Auditing ==
  [INFO] 4.1 auditd not installed. Alpine does not ship audit by default. If audit-trail compliance is required, see docs/ALPINE_DEVIATIONS.md for the busybox-syslogd + remote-collector pattern.
  [INFO] 4.2 busybox-syslogd in use. Adequate for single-host logs; CIS-grade compliance requires rsyslog or syslog-ng forwarding to a hardened collector.
  [PASS] ownership on /var/log is root:root
  [PASS] 4.2.3 no world-readable files under /var/log

== 5 Access, Authentication and Authorization ==
  [FAIL] 5.1.1 no cron daemon installed
         remediate: apk add dcron && rc-update add crond default
  [PASS] mode on /etc/ssh/sshd_config is 600
  [FAIL] 5.2 sshd: x11forwarding = yes (expected no)
         remediate: set 'x11forwarding no' in /etc/ssh/sshd_config
  [FAIL] 5.2 sshd: permitrootlogin not set (expected no)
         remediate: add 'permitrootlogin no' to /etc/ssh/sshd_config && rc-service sshd reload
  [PASS] 5.2 sshd: protocol = 2
  [INFO] 5.3 PAM not installed. Alpine often runs without PAM; if you need 5.3.* compliance, install 'linux-pam'.

== 6 System Maintenance ==
  [PASS] mode on /etc/passwd is 644
  [PASS] mode on /etc/shadow is 000
  [PASS] ownership on /etc/shadow is root:shadow
  [PASS] 6.1.10 no world-writable files
  [PASS] 6.1.11/12 no unowned / ungrouped files
  [INFO] 6.1.13 SUID binary count: 14 (review against a known baseline)
  [PASS] 6.2.1 no accounts with empty password fields
  [PASS] 6.2.5 only 'root' has UID 0
  [PASS] 6.2.6 root PATH has no empty or '.' element

== Summary ==
  total checks : 67
  pass         : 53
  fail         : 7
  info         : 5
  skip         : 2
```

Exit code is `1` because at least one `[FAIL]` was emitted. CI pipelines can
gate deploys on this exit code.
