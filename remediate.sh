#!/bin/sh
#
# remediate.sh — apply a curated subset of CIS hardening fixes for Alpine.
#
# Two modes:
#   --dry-run   print the change set that WOULD be applied (default)
#   --apply     actually write the changes (requires root)
#
# Scope: sysctl hardening, default umask, sshd config baseline, world-
# writable directory sticky bits. Anything that risks lockout (firewall,
# SSH keys) is intentionally NOT here — review the audit report and apply
# those by hand.
#
set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"

MODE="dry-run"
case "${1:-}" in
    --apply)    MODE="apply" ;;
    --dry-run|"") MODE="dry-run" ;;
    -h|--help)
        cat <<'EOF'
remediate.sh — apply a SAFE subset of CIS hardening to Alpine.

Usage:
  ./remediate.sh --dry-run   # default; just print the changes
  ./remediate.sh --apply     # actually write them (root required)

Out of scope (do these by hand after reviewing audit.sh output):
  - firewall rules               (lockout risk)
  - sshd PermitRootLogin no      (lockout if no other admin user)
  - PAM stanzas                  (lockout if misconfigured)
  - removing existing services   (downtime risk)
EOF
        exit 0
        ;;
    *)
        printf 'unknown flag: %s\n' "$1" >&2
        exit 2
        ;;
esac

if [ "$MODE" = "apply" ] && [ "$(id -u)" -ne 0 ]; then
    printf 'ERROR: --apply requires root.\n' >&2
    exit 1
fi

do_write() {
    _path="$1"; _content="$2"
    if [ "$MODE" = "dry-run" ]; then
        printf '  [dry-run] would write %s:\n' "$_path"
        printf '%s\n' "$_content" | sed 's/^/      | /'
    else
        printf '%s\n' "$_content" > "$_path"
        info "wrote $_path"
    fi
}

do_chmod() {
    _mode="$1"; _path="$2"
    if [ ! -e "$_path" ]; then return; fi
    if [ "$MODE" = "dry-run" ]; then
        printf '  [dry-run] would chmod %s %s\n' "$_mode" "$_path"
    else
        chmod "$_mode" "$_path"
        info "chmod $_mode $_path"
    fi
}

section "Remediation plan ($MODE)"

# ---------- sysctl baseline ----------
SYSCTL_FILE=/etc/sysctl.d/99-cis.conf
SYSCTL_BODY='# CIS hardening baseline applied by cis-alpine-hardening/remediate.sh
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2'
do_write "$SYSCTL_FILE" "$SYSCTL_BODY"
if [ "$MODE" = "apply" ]; then
    sysctl --system >/dev/null
fi

# ---------- default umask ----------
UMASK_FILE=/etc/profile.d/cis-umask.sh
UMASK_BODY='# CIS 5.4.4 — default umask
umask 027'
do_write "$UMASK_FILE" "$UMASK_BODY"
do_chmod 644 "$UMASK_FILE"

# ---------- core dumps off ----------
LIMITS_LINE='*    hard    core    0'
if ! grep -Fq "$LIMITS_LINE" /etc/security/limits.conf 2>/dev/null; then
    if [ "$MODE" = "dry-run" ]; then
        printf '  [dry-run] would append to /etc/security/limits.conf:\n      | %s\n' "$LIMITS_LINE"
    else
        printf '%s\n' "$LIMITS_LINE" >> /etc/security/limits.conf
        info "appended hard core 0 to /etc/security/limits.conf"
    fi
fi

# ---------- sshd safer defaults (no PermitRootLogin / PasswordAuthentication changes) ----------
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-cis-baseline.conf
SSHD_BODY='# CIS-aligned sshd hardening (non-lockout-risk subset).
Protocol 2
LogLevel INFO
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60'
if [ -d /etc/ssh/sshd_config.d ] || mkdir -p /etc/ssh/sshd_config.d 2>/dev/null; then
    do_write "$SSHD_DROPIN" "$SSHD_BODY"
    do_chmod 600 "$SSHD_DROPIN"
    if [ "$MODE" = "apply" ] && rc-service -e sshd 2>/dev/null; then
        rc-service sshd reload >/dev/null 2>&1 || true
    fi
fi

# ---------- sticky bit on world-writable dirs ----------
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | while read -r d; do
    if [ "$MODE" = "dry-run" ]; then
        printf '  [dry-run] would chmod +t %s\n' "$d"
    else
        chmod +t "$d"
        info "chmod +t $d"
    fi
done

print_summary || true
printf '\nReminder: re-run ./audit.sh after applying to confirm.\n'
