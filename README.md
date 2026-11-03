# mrjoshuap.ezcve

Ansible roles that audit Linux hosts for individual CVEs. A role may also
apply a limited mitigation. Mitigation stays off unless that role's switch is
set. [CVE-2026-98432](https://www.cve.org/) is the first role.

The default run changes nothing. Each host gets a text summary and a fact
named for the role, such as `cve_2026_98432_check_summary`. `become` is
required for checks that read process names. If privilege escalation fails,
the role still reports what it can.

Guides: [user guide](https://mrjoshuap.github.io/ansible-ezcve/user-guide/),
[CVEs](https://mrjoshuap.github.io/ansible-ezcve/cves/),
[CVE-2026-98432](https://mrjoshuap.github.io/ansible-ezcve/cves/cve-2026-98432/),
[dashboard](https://mrjoshuap.github.io/ansible-ezcve/dashboard.html),
[developer guide](https://mrjoshuap.github.io/ansible-ezcve/developer-guide/),
[changelog](https://github.com/mrjoshuap/ansible-ezcve/blob/main/CHANGELOG.md).

## Roles

| Role | Audit | Mitigation |
| --- | --- | --- |
| `cve_2026_98432_check` | Linux IPv4 TCP use-after-free in `inet_opt` / `ireq_opt` | Optional, off by default |

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

Other roles use the same play shape. The [CVE list](https://mrjoshuap.github.io/ansible-ezcve/cves/)
is the index.

## Mitigation

Off by default. Turning it on is idempotent and is not a substitute for the
vendor fix. The [CVE-2026-98432 page](https://mrjoshuap.github.io/ansible-ezcve/cves/cve-2026-98432/)
covers sysctl, nftables, and iptables behavior for that role.

```yaml
roles:
  - role: mrjoshuap.ezcve.cve_2026_98432_check
    vars:
      cve_2026_98432_check_apply_mitigation: true
      cve_2026_98432_check_drop_ipv4_options: true
```

## Reports

Set `<role>_report_dir` to a controller directory. The role writes
`<directory>/<inventory_hostname>.json`. Open the
[dashboard](https://mrjoshuap.github.io/ansible-ezcve/dashboard.html) and
choose those files. The page reads them in the browser. They are not uploaded.

## License

MIT. See [LICENSE](LICENSE).
