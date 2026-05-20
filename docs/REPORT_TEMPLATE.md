# Finding report template

Use this template when promoting an `audit.sh` finding into a deliverable
(internal ticket, customer report, audit evidence pack). The fields map
directly onto how regulated customers want findings documented.

---

## Finding ID

`CIS-<section>.<sub>` — e.g. `CIS-5.2.10`. Match the CIS control ID exactly
so cross-referencing back to the benchmark is one click.

## Title

A single sentence describing the gap. e.g. `SSH root login is not disabled
on host db-prod-02`.

## Affected host(s)

- Hostname / IP
- OS + kernel
- Role (web frontend, database, build agent, …)
- Owner / on-call team

## CIS reference

- Benchmark: CIS Distribution-Independent Linux Benchmark v2.0.0
- Control: e.g. `5.2.10 Ensure SSH root login is disabled`
- Profile: L1 / L2
- Scored: yes / no

## Observed state

Paste the relevant evidence verbatim. e.g.:

```
$ grep -i '^permitrootlogin' /etc/ssh/sshd_config
PermitRootLogin yes
```

## Expected state

What the benchmark requires. e.g. `PermitRootLogin no` in `/etc/ssh/sshd_config`.

## Risk

- **Likelihood:** low / medium / high — and *why*. e.g. "high" because the
  host has a public IP and SSH is exposed on tcp/22.
- **Impact:** what an attacker gains by exploiting the gap. e.g. immediate
  root on a Tier-1 database host.
- **CVSS v3.1:** e.g. `7.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)`. Justify
  each metric — recruiters and auditors both ask for the rationale, not just
  the number.

## Remediation

1. The exact change. e.g. `set PermitRootLogin no in /etc/ssh/sshd_config`.
2. The service action required. e.g. `rc-service sshd reload`.
3. A verification step. e.g. re-run `audit.sh 5` and confirm `[PASS] 5.2.10`.

## Rollback

What to do if the change breaks something. Always include this — it's how a
customer knows the recommendation is real.

## References

- [CIS Benchmark][cis]
- Any CVE, advisory, or vendor doc that strengthens the finding.

[cis]: https://www.cisecurity.org/benchmark/distribution_independent_linux
