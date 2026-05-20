#!/bin/sh
# Section 5 — Access, Authentication and Authorization
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 5.

section "5 Access, Authentication and Authorization"

# ---------- 5.1 Cron ----------
# 5.1.1 cron daemon — Alpine ships busybox crond, optionally dcron / cronie.
if rc-service -e crond 2>/dev/null; then
    if rc-status default 2>/dev/null | grep -q '^ crond'; then
        pass "5.1.1 crond enabled in default runlevel"
    else
        fail "5.1.1 crond not enabled" "remediate: rc-update add crond default"
    fi
else
    fail "5.1.1 no cron daemon installed" \
         "remediate: apk add dcron && rc-update add crond default"
fi

# 5.1.2 - 5.1.7  cron file permissions
for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    if [ -e "$f" ]; then
        check_mode  "$f" 600
        check_owner "$f" root:root
    fi
done

# 5.1.8 cron / at restricted to authorized users
if [ -f /etc/cron.allow ]; then
    check_mode  /etc/cron.allow 600
    check_owner /etc/cron.allow root:root
fi
if [ -f /etc/at.allow ]; then
    check_mode  /etc/at.allow 600
    check_owner /etc/at.allow root:root
fi
if [ -f /etc/cron.deny ]; then
    fail "5.1.8 /etc/cron.deny exists (CIS requires allow-list)" \
         "remediate: rm /etc/cron.deny && create /etc/cron.allow"
fi

# ---------- 5.2 SSH ----------
sshd_cfg=/etc/ssh/sshd_config
if [ ! -f "$sshd_cfg" ]; then
    info "5.2 sshd_config not found — sshd may not be installed"
else
    check_mode  "$sshd_cfg" 600
    check_owner "$sshd_cfg" root:root

    # Helper: assert a setting exactly matches an expected value.
    sshd_assert() {
        _key="$1"; _expected="$2"
        _actual=$(grep -Ei "^[[:space:]]*${_key}[[:space:]]+" "$sshd_cfg" | awk '{print tolower($2)}' | tail -n 1)
        if [ -z "$_actual" ]; then
            fail "5.2 sshd: $_key not set (expected $_expected)" \
                 "remediate: add '$_key $_expected' to $sshd_cfg && rc-service sshd reload"
        elif [ "$_actual" = "$_expected" ]; then
            pass "5.2 sshd: $_key = $_expected"
        else
            fail "5.2 sshd: $_key = $_actual (expected $_expected)" \
                 "remediate: set '$_key $_expected' in $sshd_cfg"
        fi
    }

    sshd_assert protocol                2
    sshd_assert loglevel                info
    sshd_assert x11forwarding           no
    sshd_assert maxauthtries            4
    sshd_assert ignorerhosts            yes
    sshd_assert hostbasedauthentication no
    sshd_assert permitrootlogin         no
    sshd_assert permitemptypasswords    no
    sshd_assert permituserenvironment   no
    sshd_assert passwordauthentication  no
    sshd_assert clientaliveinterval     300
    sshd_assert clientalivecountmax     0
    sshd_assert logingracetime          60
fi

# ---------- 5.3 PAM ----------
# Alpine does not install PAM by default; skip cleanly if absent.
if [ -d /etc/pam.d ]; then
    if grep -Eq 'pam_pwquality|pam_cracklib' /etc/pam.d/* 2>/dev/null; then
        pass "5.3.1 password quality module configured"
    else
        fail "5.3.1 no pam_pwquality or pam_cracklib stanza in /etc/pam.d/" \
             "remediate: apk add linux-pam libpwquality && enable in /etc/pam.d/common-password"
    fi
    if grep -Eq 'pam_tally2|pam_faillock' /etc/pam.d/* 2>/dev/null; then
        pass "5.3.2 account lockout module configured"
    else
        fail "5.3.2 no pam_tally2 or pam_faillock configured"
    fi
else
    info "5.3 PAM not installed. Alpine often runs without PAM; if you need 5.3.* compliance, install 'linux-pam'."
fi

# ---------- 5.4 User account / shadow settings ----------
login_defs=/etc/login.defs
if [ -f "$login_defs" ]; then
    pass_max=$(awk '/^PASS_MAX_DAYS/ {print $2}' "$login_defs")
    pass_min=$(awk '/^PASS_MIN_DAYS/ {print $2}' "$login_defs")
    pass_warn=$(awk '/^PASS_WARN_AGE/ {print $2}' "$login_defs")
    [ -n "$pass_max" ]  && [ "$pass_max"  -le 365 ] && pass "5.4.1.1 PASS_MAX_DAYS $pass_max"  || fail "5.4.1.1 PASS_MAX_DAYS must be <= 365 (current: ${pass_max:-unset})"
    [ -n "$pass_min" ]  && [ "$pass_min"  -ge 7   ] && pass "5.4.1.2 PASS_MIN_DAYS $pass_min"  || fail "5.4.1.2 PASS_MIN_DAYS must be >= 7 (current: ${pass_min:-unset})"
    [ -n "$pass_warn" ] && [ "$pass_warn" -ge 7   ] && pass "5.4.1.3 PASS_WARN_AGE $pass_warn" || fail "5.4.1.3 PASS_WARN_AGE must be >= 7 (current: ${pass_warn:-unset})"
fi

# 5.4.4 default umask
if grep -Eq '^[[:space:]]*umask[[:space:]]+0?27' /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
    pass "5.4.4 default umask 027 set in /etc/profile*"
else
    fail "5.4.4 no 'umask 027' in /etc/profile" \
         "remediate: echo 'umask 027' > /etc/profile.d/cis-umask.sh"
fi

# ---------- 5.6 su restricted ----------
if grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel' /etc/pam.d/su 2>/dev/null; then
    pass "5.6 su restricted via pam_wheel"
elif [ -f /etc/suauth ]; then
    pass "5.6 /etc/suauth configured (shadow utils su restriction)"
else
    info "5.6 su access is not restricted to wheel. On Alpine, edit /etc/suauth or install linux-pam."
fi
