#!/bin/sh
# Section 2 — Services
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 2.

section "2 Services"

# ---------- 2.1 inetd services ----------
# Alpine does not install inetd by default; the CIS controls 2.1.1-2.1.10
# (chargen, daytime, discard, echo, time, rsh, talk, telnet, tftp, xinetd)
# collapse to a single "is xinetd installed" check.
check_pkg_absent xinetd
for legacy_pkg in netkit-rsh netkit-telnet talk; do
    check_pkg_absent "$legacy_pkg"
done

# ---------- 2.2 Special purpose services ----------
# 2.2.1 Time synchronization
if apk info -e chrony >/dev/null 2>&1; then
    check_service_enabled chronyd
    if grep -Eq '^[[:space:]]*server[[:space:]]+\S+' /etc/chrony/chrony.conf 2>/dev/null ||
       grep -Eq '^[[:space:]]*pool[[:space:]]+\S+'   /etc/chrony/chrony.conf 2>/dev/null; then
        pass "2.2.1.3 chrony has at least one upstream server/pool"
    else
        fail "2.2.1.3 chrony has no server/pool directive" \
             "remediate: add 'pool pool.ntp.org iburst' to /etc/chrony/chrony.conf"
    fi
elif apk info -e openntpd >/dev/null 2>&1; then
    check_service_enabled openntpd
    info "2.2.1 openntpd in use (Alpine default option)"
elif apk info -e busybox-ntpd >/dev/null 2>&1; then
    info "2.2.1 busybox-ntpd in use; acceptable but lacks chrony's drift correction"
else
    fail "2.2.1 no time synchronization client installed" \
         "remediate: apk add chrony && rc-update add chronyd default"
fi

# 2.2.2 - 2.2.14  these services should not be enabled on a hardened host
for svc_pkg in xorg-server avahi cups isc-dhcp-server openldap-servers \
               nfs-utils bind vsftpd apache2 nginx \
               dovecot samba squid net-snmp; do
    check_pkg_absent "$svc_pkg"
done

# 2.2.15 MTA local-only (Alpine often ships ssmtp / msmtp for outbound only).
if apk info -e postfix >/dev/null 2>&1; then
    if grep -Eq '^inet_interfaces[[:space:]]*=[[:space:]]*loopback-only|^inet_interfaces[[:space:]]*=[[:space:]]*127\.0\.0\.1' /etc/postfix/main.cf 2>/dev/null; then
        pass "2.2.15 postfix listens on loopback only"
    else
        fail "2.2.15 postfix is installed but not loopback-only" \
             "remediate: set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf"
    fi
else
    pass "2.2.15 no postfix installed (acceptable on a non-mail host)"
fi

# 2.2.16 rsyncd as a daemon must be disabled (the rsync client is fine).
if rc-service -e rsyncd 2>/dev/null && rc-status default 2>/dev/null | grep -q '^ rsyncd'; then
    fail "2.2.16 rsyncd daemon is enabled" \
         "remediate: rc-update del rsyncd default && rc-service rsyncd stop"
else
    pass "2.2.16 rsyncd daemon is not enabled"
fi

# ---------- 2.3 Service clients ----------
# 2.3.1-2.3.5 — legacy / cleartext clients should not be installed.
for cli_pkg in nis rsh-client talk telnet openldap-clients; do
    check_pkg_absent "$cli_pkg"
done
