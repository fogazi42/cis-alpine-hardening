#!/bin/sh
# Section 4 — Logging and Auditing
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 4.

section "4 Logging and Auditing"

# ---------- 4.1 auditd ----------
# auditd is rare on Alpine because the upstream package is glibc-centric and
# musl support has historically been spotty. If you need 4.1.* compliance,
# install audit from the testing repo and accept the maintenance burden.
if apk info -e audit >/dev/null 2>&1; then
    check_service_enabled auditd
    if [ -f /etc/audit/auditd.conf ]; then
        if grep -Eq '^[[:space:]]*max_log_file[[:space:]]*=[[:space:]]*[0-9]+' /etc/audit/auditd.conf; then
            pass "4.1.1.1 auditd max_log_file is set"
        else
            fail "4.1.1.1 max_log_file not set in /etc/audit/auditd.conf"
        fi
        if grep -Eq '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' /etc/audit/auditd.conf; then
            pass "4.1.1.3 audit logs are retained (keep_logs)"
        else
            fail "4.1.1.3 max_log_file_action is not keep_logs"
        fi
    fi
else
    info "4.1 auditd not installed. Alpine does not ship audit by default. If audit-trail compliance is required, see docs/ALPINE_DEVIATIONS.md for the busybox-syslogd + remote-collector pattern."
fi

# ---------- 4.2 System logger ----------
# Order of preference: rsyslog > syslog-ng > busybox-syslogd.
if apk info -e rsyslog >/dev/null 2>&1; then
    check_service_enabled rsyslog
    check_mode  /etc/rsyslog.conf 644
    check_owner /etc/rsyslog.conf root:root
    if grep -Eq '^\$FileCreateMode[[:space:]]+0[0246]40' /etc/rsyslog.conf 2>/dev/null; then
        pass "4.2.1.4 rsyslog default file mode is restrictive"
    else
        fail "4.2.1.4 rsyslog \$FileCreateMode is not 0640 or stricter" \
             "remediate: echo '\$FileCreateMode 0640' >> /etc/rsyslog.conf"
    fi
    if grep -Eq '^\*\.\*[[:space:]]+@@?[A-Za-z0-9.:_-]+' /etc/rsyslog.conf 2>/dev/null ||
       find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null \
         | xargs -0 -r grep -Eq '^\*\.\*[[:space:]]+@@?'; then
        pass "4.2.1.5 rsyslog ships logs to a remote host"
    else
        fail "4.2.1.5 rsyslog has no remote log target" \
             "remediate: add '*.* @@loghost.example.com:514' to /etc/rsyslog.conf"
    fi
elif apk info -e syslog-ng >/dev/null 2>&1; then
    check_service_enabled syslog-ng
    info "4.2 syslog-ng in use — adapt the rsyslog checks above to the equivalent syslog-ng destination{ } block."
elif command -v busybox >/dev/null 2>&1 && busybox --list 2>/dev/null | grep -qx syslogd; then
    info "4.2 busybox-syslogd in use. Adequate for single-host logs; CIS-grade compliance requires rsyslog or syslog-ng forwarding to a hardened collector."
else
    fail "4.2 no system logger active" \
         "remediate: apk add rsyslog && rc-update add rsyslog default"
fi

# 4.2.3 /var/log permission and ownership
if [ -d /var/log ]; then
    check_owner /var/log root:root
    # Walk the tree; any log file readable by 'other' is suspect.
    bad=$(find /var/log -type f -perm -004 2>/dev/null | head -n 3)
    if [ -z "$bad" ]; then
        pass "4.2.3 no world-readable files under /var/log"
    else
        fail "4.2.3 world-readable files under /var/log" \
             "first offenders: $(printf '%s ' $bad)"
    fi
fi
