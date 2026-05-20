#!/bin/sh
# Section 6 — System Maintenance
# Maps to CIS Distribution-Independent Linux Benchmark v2.0.0 chapter 6.

section "6 System Maintenance"

# ---------- 6.1 System file permissions ----------
check_mode  /etc/passwd  644
check_owner /etc/passwd  root:root
check_mode  /etc/shadow  000
check_owner /etc/shadow  root:shadow
check_mode  /etc/group   644
check_owner /etc/group   root:root
check_mode  /etc/gshadow 000
check_owner /etc/gshadow root:shadow

# Backup files (CIS 6.1.6 - 6.1.9)
for f in /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-; do
    [ -e "$f" ] && check_owner "$f" root:root
done

# 6.1.10 World-writable files
ww=$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 3)
if [ -z "$ww" ]; then
    pass "6.1.10 no world-writable files"
else
    fail "6.1.10 world-writable files present" \
         "first offenders: $(printf '%s ' $ww)"
fi

# 6.1.11 Unowned files
unowned=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 3)
if [ -z "$unowned" ]; then
    pass "6.1.11/12 no unowned / ungrouped files"
else
    fail "6.1.11/12 unowned or ungrouped files present" \
         "first offenders: $(printf '%s ' $unowned)"
fi

# 6.1.13 / 6.1.14 SUID & SGID inventory — these are INFO, not pass/fail.
suid_count=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
sgid_count=$(find / -xdev -type f -perm -2000 2>/dev/null | wc -l)
info "6.1.13 SUID binary count: $suid_count (review against a known baseline)"
info "6.1.14 SGID binary count: $sgid_count (review against a known baseline)"

# ---------- 6.2 User and group sanity ----------
# 6.2.1 No empty password fields in /etc/shadow
empty_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$empty_pw" ]; then
    pass "6.2.1 no accounts with empty password fields"
else
    fail "6.2.1 accounts with empty password: $empty_pw" \
         "remediate: passwd -l <user> for each"
fi

# 6.2.2 / 6.2.3 / 6.2.4 Legacy '+' entries in passwd / shadow / group
for f in /etc/passwd /etc/shadow /etc/group; do
    if grep -q '^+' "$f" 2>/dev/null; then
        fail "6.2.x legacy '+' entry in $f" "remediate: remove the line"
    else
        pass "6.2.x no legacy '+' entries in $f"
    fi
done

# 6.2.5 root is the only UID 0
uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
if [ "$uid0" = "root" ]; then
    pass "6.2.5 only 'root' has UID 0"
else
    fail "6.2.5 multiple UID 0 accounts: $uid0" \
         "remediate: change UID on the duplicate account"
fi

# 6.2.6 root PATH sanity. Wrapping with ':' on both sides means any '.' element
# always appears as ':.:'; we don't need a separate trailing-dot pattern.
case ":$PATH:" in
    *::*)    fail "6.2.6 root PATH contains an empty element" ;;
    *:.:*)   fail "6.2.6 root PATH contains '.'" ;;
    *)       pass "6.2.6 root PATH has no empty or '.' element" ;;
esac

# 6.2.7-6.2.9 home directories
bad_home=""
while IFS=: read -r user _ uid _ _ home _; do
    if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
        if [ ! -d "$home" ]; then
            bad_home="$bad_home $user(no-home)"
            continue
        fi
        owner=$(stat -c '%U' "$home" 2>/dev/null)
        if [ "$owner" != "$user" ]; then
            bad_home="$bad_home $user(owned-by-$owner)"
        fi
    fi
done < /etc/passwd
if [ -z "$bad_home" ]; then
    pass "6.2.7-9 all user home directories exist and are owned by their user"
else
    fail "6.2.7-9 home directory issues:$bad_home"
fi

# 6.2.16 / 6.2.17 duplicate UIDs / GIDs
dup_uid=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
dup_gid=$(awk -F: '{print $3}' /etc/group  | sort | uniq -d)
[ -z "$dup_uid" ] && pass "6.2.16 no duplicate UIDs" || fail "6.2.16 duplicate UIDs: $dup_uid"
[ -z "$dup_gid" ] && pass "6.2.17 no duplicate GIDs" || fail "6.2.17 duplicate GIDs: $dup_gid"
