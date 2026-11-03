# cve_2026_98432_check

Read-only audit for CVE-2026-98432 (Linux IPv4 TCP use-after-free).
Fix status, variables, mitigation, and reports are in the
[CVE-2026-98432 page](https://mrjoshuap.github.io/ansible-ezcve/cves/cve-2026-98432/).

## Example

```yaml
- name: Audit hosts for CVE-2026-98432
  hosts: all
  gather_facts: true
  become: true
  roles:
    - role: mrjoshuap.ezcve.cve_2026_98432_check
```

The role does not change hosts unless `cve_2026_98432_check_apply_mitigation`
is true.

## Risk

- `high`: vulnerable kernel and an MPTCP listener
- `medium`: vulnerable kernel, no MPTCP listener
- `low`: fixed, or older than 4.4
- `unknown`: changelog and version data could not decide
