# cve_2026_98432_check

Read-only audit for CVE-2026-98432 (Linux IPv4 TCP use-after-free). The
repository [README](../../README.md) is the full guide. This file is enough
to run the role after it has been copied on its own.

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

## Fix status as of 2026-11-03

Ubuntu 26.10 generic is fixed in `7.3.0-10.10`. Ubuntu 22.04, 24.04, and
26.04 generic fixes were still only in `-proposed` (`5.15.0-203.213`,
`6.8.0-149.149`, `7.0.0-43.43`, plus the HWE builds in defaults). Ubuntu
20.04 and older have no published fix. RHEL-family 8.10, 9.8, and 10.2, the
listed EUS streams, Debian 12, Debian 13, and current Fedora upstream stables
are in `defaults/main.yml`.

A changelog line matching `CVE-2026-98432` or `free inet_opt and ireq_opt`
marks the running kernel fixed even when the version table is older. A kernel
update does not take effect until reboot. `reboot_required` is true when a
fixed package is installed and a vulnerable kernel is still running.

## Override the version data

Extra vars replace the whole mapping. Copy `cve_2026_98432_check_fixed_kernels`
and change the release you need. Quote keys such as `"8.10"`.

## Risk

- `high`: vulnerable kernel and an MPTCP listener
- `medium`: vulnerable kernel, no MPTCP listener
- `low`: fixed, or older than 4.4
- `unknown`: changelog and version data could not decide

`mptcp_enabled_without_listeners` notes `net.mptcp.enabled=1` with no current
listener. New MPTCP sockets can still appear.

## Tags

`cve_check` and `report` run the audit. `mitigate` runs only the optional
mitigation tasks, which stay skipped while the switch is false.

## Optional mitigation

```yaml
cve_2026_98432_check_apply_mitigation: true
cve_2026_98432_check_drop_ipv4_options: true
```

This persists `net.mptcp.enabled=0` and, when requested, loads an nftables or
iptables rule that drops IPv4 TCP packets carrying IP options. It needs the
`ansible.posix` collection. It does not fix the kernel.

## Facts

`cve_2026_98432_check_summary`, `cve_2026_98432_check_risk`, and
`cve_2026_98432_check_kernel_status`. Set `cve_2026_98432_check_report_dir`
to write `<inventory_hostname>.json` on the controller. Set
`cve_2026_98432_check_report_csv` to also write a one-row CSV.
