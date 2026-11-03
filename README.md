# CVE-2026-98432 audit

Read-only Ansible role that reports whether a Linux host is running a kernel
fixed for [CVE-2026-98432](https://www.cve.org/) (IPv4 TCP use-after-free in
`inet_opt` / `ireq_opt`). It supports RHEL-family 8, 9, and 10 (RHEL, Rocky,
Alma, CentOS Stream), Fedora, Debian, and Ubuntu.

The default run changes nothing. Each host gets a text summary and the fact
`cve_2026_98432_check_summary`. `become` is required for `ss -Mlnp` so the
summary can include process names. Changelog reads and sysctl reads do not
need it. If privilege escalation fails, the role lists listeners without
process names.

Guides: [user guide](https://mrjoshuap.github.io/ansible-ezcve/user-guide/),
[developer guide](https://mrjoshuap.github.io/ansible-ezcve/developer-guide/),
[changelog](https://github.com/mrjoshuap/ansible-ezcve/blob/main/CHANGELOG.md).

## Install

```yaml
collections:
  - name: mrjoshuap.ezcve
    version: ">=1.0.0"
```

That range stays on stable releases.

## Audit

```yaml
- name: Audit hosts for CVE-2026-98432
  hosts: all
  gather_facts: true
  become: true
  roles:
    - role: mrjoshuap.ezcve.cve_2026_98432_check
```

## Mitigation

Off by default. Turning it on is idempotent and is not a substitute for a
fixed kernel plus a reboot. The [user guide](https://mrjoshuap.github.io/ansible-ezcve/user-guide/)
covers sysctl, nftables, and iptables behavior.

```yaml
roles:
  - role: mrjoshuap.ezcve.cve_2026_98432_check
    vars:
      cve_2026_98432_check_apply_mitigation: true
      cve_2026_98432_check_drop_ipv4_options: true
```

## License

MIT. See [LICENSE](LICENSE).
