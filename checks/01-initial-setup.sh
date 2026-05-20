#!/bin/sh
# Section 1 — Initial Setup
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 1.
# Some controls (GRUB password, SELinux/AppArmor) are RHEL/Ubuntu-centric.
# Alpine deviations are flagged in docs/ALPINE_DEVIATIONS.md.

section "1 Initial Setup"

# ---------- 1.1.1 Disable unused filesystems ----------
# CIS recommends disabling obsolete or rarely-used filesystem modules so a
# local attacker cannot mount removable media as a vehicle for malicious content.
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    check_module_disabled "$mod"
done

# 1.1.21 Ensure sticky bit is set on all world-writable directories
ww=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -n 5)
if [ -z "$ww" ]; then
    pass "1.1.21 no world-writable directories missing sticky bit"
else
    fail "1.1.21 world-writable directories missing sticky bit" \
         "first offenders: $(printf '%s ' $ww)"
fi

# 1.1.22 Disable automounting (autofs uncommon on Alpine)
check_pkg_absent autofs

# ---------- 1.3 Filesystem integrity checking ----------
# 1.3.1 AIDE installed
check_pkg_present aide

# ---------- 1.4 Secure Boot ----------
# Alpine usually boots via syslinux/extlinux, not GRUB. We check whichever
# loader is present.
if [ -f /etc/update-extlinux.conf ] || [ -f /boot/extlinux.conf ]; then
    info "1.4 extlinux detected; CIS GRUB password controls do not apply directly. See ALPINE_DEVIATIONS.md."
elif [ -f /boot/grub/grub.cfg ]; then
    check_mode  /boot/grub/grub.cfg 600
    check_owner /boot/grub/grub.cfg root:root
elif [ -f /boot/grub2/grub.cfg ]; then
    check_mode  /boot/grub2/grub.cfg 600
    check_owner /boot/grub2/grub.cfg root:root
else
    skip "1.4 no GRUB/extlinux config found"
fi

# ---------- 1.5 Additional process hardening ----------
# 1.5.1 Restrict core dumps
check_sysctl fs.suid_dumpable 0
if grep -Eq '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf 2>/dev/null ||
   grep -rEq '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.d/ 2>/dev/null; then
    pass "1.5.1 hard core 0 set in limits.conf"
else
    fail "1.5.1 no 'hard core 0' rule in /etc/security/limits.conf" \
         "remediate: echo '*    hard    core    0' >> /etc/security/limits.conf"
fi

# 1.5.3 ASLR
check_sysctl kernel.randomize_va_space 2

# 1.5.4 prelink — Alpine doesn't ship prelink, but check anyway.
check_pkg_absent prelink

# ---------- 1.6 Mandatory Access Control ----------
# Alpine ships neither SELinux nor AppArmor by default. apparmor IS in the
# community repo for those who opt in; flag the state honestly.
if apk info -e apparmor >/dev/null 2>&1; then
    pass "1.6.1 apparmor package installed"
    if [ -d /sys/kernel/security/apparmor ]; then
        pass "1.6.3 apparmor LSM is loaded"
    else
        fail "1.6.3 apparmor installed but LSM is not loaded" \
             "remediate: add 'lsm=apparmor' to kernel cmdline"
    fi
else
    info "1.6 no MAC framework installed. Alpine does not ship SELinux; AppArmor is available via 'apk add apparmor'."
fi

# ---------- 1.7 Warning banners ----------
for f in /etc/motd /etc/issue /etc/issue.net; do
    if [ -f "$f" ]; then
        check_mode  "$f" 644
        check_owner "$f" root:root
        if grep -Eq '\\(v|r|m|s)' "$f" 2>/dev/null; then
            fail "1.7 $f leaks OS info via escape sequences" \
                 "remediate: remove \\v \\r \\m \\s tokens"
        else
            pass "1.7 $f does not leak OS information"
        fi
    else
        skip "1.7 $f not present"
    fi
done
