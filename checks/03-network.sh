#!/bin/sh
# Section 3 — Network Configuration
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 3.

section "3 Network Configuration"

# ---------- 3.1 Host-only network parameters ----------
check_sysctl net.ipv4.ip_forward                         0
check_sysctl net.ipv4.conf.all.send_redirects            0
check_sysctl net.ipv4.conf.default.send_redirects        0

# ---------- 3.2 Host + router network parameters ----------
check_sysctl net.ipv4.conf.all.accept_source_route       0
check_sysctl net.ipv4.conf.default.accept_source_route   0
check_sysctl net.ipv4.conf.all.accept_redirects          0
check_sysctl net.ipv4.conf.default.accept_redirects      0
check_sysctl net.ipv4.conf.all.secure_redirects          0
check_sysctl net.ipv4.conf.default.secure_redirects      0
check_sysctl net.ipv4.conf.all.log_martians              1
check_sysctl net.ipv4.conf.default.log_martians          1
check_sysctl net.ipv4.icmp_echo_ignore_broadcasts        1
check_sysctl net.ipv4.icmp_ignore_bogus_error_responses  1
check_sysctl net.ipv4.conf.all.rp_filter                 1
check_sysctl net.ipv4.conf.default.rp_filter             1
check_sysctl net.ipv4.tcp_syncookies                     1

# IPv6 hardening — only checked when IPv6 is enabled.
if [ -d /proc/sys/net/ipv6 ]; then
    check_sysctl net.ipv6.conf.all.accept_ra             0
    check_sysctl net.ipv6.conf.default.accept_ra         0
    check_sysctl net.ipv6.conf.all.accept_redirects      0
    check_sysctl net.ipv6.conf.default.accept_redirects  0
else
    skip "3.x IPv6 is disabled on this host"
fi

# ---------- 3.4 Uncommon protocols ----------
for proto in dccp sctp rds tipc; do
    check_module_disabled "$proto"
done

# ---------- 3.5 Firewall ----------
# Alpine ships iptables/nftables. awall is the recommended wrapper.
if command -v awall >/dev/null 2>&1; then
    if awall list 2>/dev/null | grep -qE 'enabled'; then
        pass "3.5 awall has at least one enabled policy"
    else
        fail "3.5 awall installed but no policy enabled" \
             "remediate: see https://wiki.alpinelinux.org/wiki/Awall"
    fi
elif command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -qE 'chain (input|forward|output)'; then
        pass "3.5 nftables ruleset is present"
    else
        fail "3.5 nft is installed but ruleset is empty" \
             "remediate: load a base ruleset from /etc/nftables/"
    fi
elif command -v iptables >/dev/null 2>&1; then
    if iptables -L INPUT 2>/dev/null | grep -q 'policy DROP'; then
        pass "3.5 iptables INPUT default policy is DROP"
    else
        fail "3.5 iptables INPUT default policy is not DROP" \
             "remediate: iptables -P INPUT DROP   (after allowing loopback + established)"
    fi
else
    fail "3.5 no host firewall installed" \
         "remediate: apk add iptables awall && rc-update add iptables default"
fi

# 3.6 Wireless interfaces should be disabled on servers.
if ls /sys/class/net 2>/dev/null | while read -r iface; do
        if [ -d "/sys/class/net/$iface/wireless" ]; then
            printf '%s ' "$iface"
        fi
   done | grep -q .; then
    fail "3.6 wireless interface(s) present and not disabled"
else
    pass "3.6 no active wireless interfaces"
fi
