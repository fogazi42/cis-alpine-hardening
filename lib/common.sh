#!/bin/sh
# Common helpers for CIS Alpine hardening checks.
# POSIX sh (BusyBox ash compatible). No bashisms.

# Counters shared across check files.
PASS_COUNT=${PASS_COUNT:-0}
FAIL_COUNT=${FAIL_COUNT:-0}
INFO_COUNT=${INFO_COUNT:-0}
SKIP_COUNT=${SKIP_COUNT:-0}

# Colors (off by default; enabled if stdout is a tty).
if [ -t 1 ] && [ "${NO_COLOR:-0}" = "0" ]; then
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_YELLOW=$(printf '\033[33m')
    C_BLUE=$(printf '\033[34m')
    C_RESET=$(printf '\033[0m')
else
    C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_RESET=''
fi

section() {
    printf '\n%s== %s ==%s\n' "$C_BLUE" "$1" "$C_RESET"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '  %s[PASS]%s %s\n' "$C_GREEN" "$C_RESET" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1"
    if [ -n "$2" ]; then
        printf '         %s\n' "$2"
    fi
}

info() {
    INFO_COUNT=$((INFO_COUNT + 1))
    printf '  %s[INFO]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    printf '  %s[SKIP]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

# Compare a file's octal mode with an expected value.
# Usage: check_mode <path> <expected_mode>  e.g.  check_mode /etc/passwd 644
check_mode() {
    _path="$1"; _expected="$2"
    [ -e "$_path" ] || { skip "mode check: $_path not present"; return; }
    _actual=$(stat -c '%a' "$_path" 2>/dev/null)
    if [ "$_actual" = "$_expected" ]; then
        pass "mode on $_path is $_expected"
    else
        fail "mode on $_path is $_actual (expected $_expected)" \
             "remediate: chmod $_expected $_path"
    fi
}

# Check a file owner:group.
# Usage: check_owner <path> <user>:<group>
check_owner() {
    _path="$1"; _expected="$2"
    [ -e "$_path" ] || { skip "owner check: $_path not present"; return; }
    _actual=$(stat -c '%U:%G' "$_path" 2>/dev/null)
    if [ "$_actual" = "$_expected" ]; then
        pass "ownership on $_path is $_expected"
    else
        fail "ownership on $_path is $_actual (expected $_expected)" \
             "remediate: chown $_expected $_path"
    fi
}

# Confirm a kernel module is blocked (CIS 1.1.1.* style).
# Alpine ships a slim kernel; many obsolete fs modules are simply absent.
check_module_disabled() {
    _mod="$1"
    if ! command -v modprobe >/dev/null 2>&1; then
        skip "$_mod: modprobe not available on this host"
        return
    fi
    _result=$(modprobe -n -v "$_mod" 2>&1 | head -n 1)
    case "$_result" in
        *install*/bin/true*|*"insmod /dev/null"*)
            pass "$_mod: module load is short-circuited"
            ;;
        FATAL*"Module $_mod not found"*)
            pass "$_mod: module not present in kernel image"
            ;;
        *)
            if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$_mod"; then
                fail "$_mod: module is currently LOADED" \
                     "remediate: rmmod $_mod && echo 'install $_mod /bin/true' >> /etc/modprobe.d/cis.conf"
            else
                info "$_mod: not loaded, but load is not explicitly blocked"
            fi
            ;;
    esac
}

# Read sysctl value and compare to expected.
check_sysctl() {
    _key="$1"; _expected="$2"
    _actual=$(sysctl -n "$_key" 2>/dev/null) || {
        skip "sysctl: $_key not present on this kernel"
        return
    }
    if [ "$_actual" = "$_expected" ]; then
        pass "sysctl $_key = $_expected"
    else
        fail "sysctl $_key = $_actual (expected $_expected)" \
             "remediate: echo '$_key = $_expected' >> /etc/sysctl.d/99-cis.conf && sysctl --system"
    fi
}

# Confirm an OpenRC service is in the requested state.
# Usage: check_service_disabled <service>  /  check_service_enabled <service>
check_service_disabled() {
    _svc="$1"
    if rc-service -e "$_svc" 2>/dev/null; then
        if rc-status default 2>/dev/null | grep -q "^ ${_svc}"; then
            fail "$_svc is enabled" \
                 "remediate: rc-update del $_svc default && rc-service $_svc stop"
        else
            pass "$_svc is not in any runlevel"
        fi
    else
        pass "$_svc is not installed"
    fi
}

check_service_enabled() {
    _svc="$1"
    if ! rc-service -e "$_svc" 2>/dev/null; then
        fail "$_svc is not installed" \
             "remediate: apk add $_svc"
        return
    fi
    if rc-status default 2>/dev/null | grep -q "^ ${_svc}"; then
        pass "$_svc is enabled at default runlevel"
    else
        fail "$_svc is installed but not in default runlevel" \
             "remediate: rc-update add $_svc default && rc-service $_svc start"
    fi
}

# Confirm an apk package is absent (used for CIS "ensure X is not installed").
check_pkg_absent() {
    _pkg="$1"
    if apk info -e "$_pkg" >/dev/null 2>&1; then
        fail "package $_pkg is installed" \
             "remediate: apk del $_pkg"
    else
        pass "package $_pkg is not installed"
    fi
}

# Confirm an apk package is present.
check_pkg_present() {
    _pkg="$1"
    if apk info -e "$_pkg" >/dev/null 2>&1; then
        pass "package $_pkg is installed"
    else
        fail "package $_pkg is missing" \
             "remediate: apk add $_pkg"
    fi
}

print_summary() {
    _total=$((PASS_COUNT + FAIL_COUNT + INFO_COUNT + SKIP_COUNT))
    printf '\n%s== Summary ==%s\n' "$C_BLUE" "$C_RESET"
    printf '  total checks : %d\n' "$_total"
    printf '  %spass%s         : %d\n' "$C_GREEN" "$C_RESET" "$PASS_COUNT"
    printf '  %sfail%s         : %d\n' "$C_RED" "$C_RESET" "$FAIL_COUNT"
    printf '  info         : %d\n' "$INFO_COUNT"
    printf '  skip         : %d\n' "$SKIP_COUNT"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        return 1
    fi
    return 0
}
