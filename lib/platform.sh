#!/bin/sh
# Detect Alpine version + init system so checks can branch correctly.

detect_alpine() {
    if [ ! -f /etc/alpine-release ]; then
        printf 'WARN: /etc/alpine-release not found — this toolkit targets Alpine.\n' >&2
        printf '      Continuing in best-effort mode.\n' >&2
        ALPINE_VERSION="unknown"
        return
    fi
    ALPINE_VERSION=$(cat /etc/alpine-release)
    printf 'Alpine version detected: %s\n' "$ALPINE_VERSION"
}

detect_init() {
    if command -v openrc >/dev/null 2>&1 || [ -d /etc/runlevels ]; then
        INIT_SYSTEM="openrc"
    elif command -v systemctl >/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="unknown"
    fi
    printf 'Init system    : %s\n' "$INIT_SYSTEM"
}

detect_firewall() {
    # Alpine commonly uses awall (an iptables wrapper) or plain iptables / nftables.
    if command -v awall >/dev/null 2>&1; then
        FIREWALL="awall"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL="iptables"
    else
        FIREWALL="none"
    fi
    printf 'Firewall       : %s\n' "$FIREWALL"
}

detect_logger() {
    # Alpine usually ships syslog-ng or busybox syslogd; rsyslog is optional.
    if apk info -e rsyslog >/dev/null 2>&1; then
        LOGGER="rsyslog"
    elif apk info -e syslog-ng >/dev/null 2>&1; then
        LOGGER="syslog-ng"
    elif command -v busybox >/dev/null 2>&1 && busybox --list 2>/dev/null | grep -qx syslogd; then
        LOGGER="busybox-syslogd"
    else
        LOGGER="none"
    fi
    printf 'Logger         : %s\n' "$LOGGER"
}
