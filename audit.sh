#!/bin/sh
#
# audit.sh — run the CIS Distribution-Independent Linux Benchmark v2.0.0
#            checks adapted for Alpine Linux.
#
# Usage:
#   ./audit.sh                      # run every section
#   ./audit.sh 1 4                  # run only sections 1 and 4
#   ./audit.sh --help
#
# Exit code: 0 if every check passed, 1 if any failed.
#
set -eu

SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
. "$SELF_DIR/lib/platform.sh"

usage() {
    cat <<'EOF'
audit.sh — CIS Distribution-Independent Linux Benchmark v2.0.0 audit, adapted
           for Alpine Linux (musl + BusyBox + OpenRC).

Usage:
  ./audit.sh [SECTION ...]
  ./audit.sh --help

Sections:
  1  Initial Setup           (filesystem, secure boot, process hardening, MAC)
  2  Services                (inetd, special-purpose, service clients)
  3  Network Configuration   (sysctl, firewall, uncommon protocols)
  4  Logging and Auditing    (auditd, rsyslog / syslog-ng / busybox-syslogd)
  5  Access & Authentication (cron, ssh, pam, user accounts)
  6  System Maintenance      (file permissions, user/group sanity)

Examples:
  ./audit.sh                # run all six sections
  ./audit.sh 1 5            # run only Initial Setup and Access checks

Notes:
  - Some CIS controls assume RHEL/Ubuntu conventions (GRUB, systemd-journald,
    SELinux, auditd) that Alpine does not ship by default. Those checks emit
    [INFO] or [SKIP] with the Alpine equivalent noted in docs/ALPINE_DEVIATIONS.md.
  - Run as root to avoid false negatives on /etc/shadow style checks.

EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    printf 'WARN: not running as root; checks against /etc/shadow, /root, sysctl etc.\n' >&2
    printf '      will SKIP or report misleading results.\n\n' >&2
fi

detect_alpine
detect_init
detect_firewall
detect_logger

# Default: all sections. Otherwise, only the positional args.
if [ "$#" -eq 0 ]; then
    SECTIONS="1 2 3 4 5 6"
else
    SECTIONS="$*"
fi

for sec in $SECTIONS; do
    case "$sec" in
        1) . "$SELF_DIR/checks/01-initial-setup.sh"  ;;
        2) . "$SELF_DIR/checks/02-services.sh"       ;;
        3) . "$SELF_DIR/checks/03-network.sh"        ;;
        4) . "$SELF_DIR/checks/04-logging.sh"        ;;
        5) . "$SELF_DIR/checks/05-access.sh"         ;;
        6) . "$SELF_DIR/checks/06-maintenance.sh"    ;;
        *) printf 'unknown section: %s (expected 1..6)\n' "$sec" >&2 ;;
    esac
done

print_summary
