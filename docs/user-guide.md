# User guide

Reference for `mrjoshuap.ezcve.cve_2026_98432_check`. Install steps and the
audit and mitigation examples are on the
[collection page](https://galaxy.ansible.com/ui/repo/published/mrjoshuap/ezcve/).
Building and publishing the collection is in the [developer guide](developer-guide.md).

## Fix status as of 2026-11-03

These are the versions shipped in `defaults/main.yml`. Replace that mapping
when a vendor publishes a newer minimum. A changelog hit always wins over the
table.

| Family | Fixed in | Notes |
| --- | --- | --- |
| RHEL / Rocky / Alma / CentOS Stream 8.10 | `kernel` >= `4.18.0-553.182.1.el8_10` | Also 8.8 EUS `4.18.0-477.178.1.el8_8` |
| RHEL-family 9.8 | `kernel` >= `5.14.0-687.64.1.el9_8` | Also 9.2, 9.4, and 9.6 EUS entries |
| RHEL-family 10.2 | `kernel` >= `6.12.0-211.72.1.el10_2` | Also 10.0 EUS |
| RHEL 8.10 real-time | `4.18.0-553.182.1.rt7.523.el8_10` | Other RT builds need a changelog hit |
| Fedora | Upstream stable | `5.10.272`, `5.15.223`, `6.1.190`, `6.6.159`, `6.12.113`, `6.18.56`, `7.2.10`, `7.3` |
| Debian 12 | `linux` >= `6.1.190-1` or `linux-6.12` >= `6.12.113-1~deb12u1` | |
| Debian 13 | `linux` >= `6.12.113-1` | |
| Ubuntu 26.10 generic | `7.3.0-10.10` | In the updates pocket |
| Ubuntu 26.04 / 24.04 / 22.04 generic | `7.0.0-43.43`, `6.8.0-149.149`, `5.15.0-203.213` | In `-proposed` only, as of this date |
| Ubuntu 20.04 and older | No published fix | Kernels older than 4.4 are not affected |

Ubuntu HWE and cloud flavors (`aws`, `azure`, `gcp`, and others) are not
compared to the generic ABI numbers. Those hosts are fixed only when the
running kernel changelog names the CVE. Add a flavor rule to the Ubuntu list
when you want a version fallback for that flavor.

A kernel package update does nothing until the host boots that kernel. The
summary says so. `reboot_required` is true when a fixed package is installed
and the running kernel is still older.

## Risk

| Risk | Meaning |
| --- | --- |
| `high` | Vulnerable kernel and at least one MPTCP listener |
| `medium` | Vulnerable kernel, no MPTCP listener |
| `low` | Fixed kernel, or a kernel older than 4.4 |
| `unknown` | The changelog and the version table could not decide |

`mptcp_enabled_without_listeners` is true when `net.mptcp.enabled=1` and no
listener is open. New MPTCP sockets can still appear. Go 1.24 and later open
MPTCP listeners by default on Linux.

Disabling MPTCP is not a fix. The bug is in IPv4 TCP handshake handling.

## What the role collects

- OS id normalized to `redhat`, `fedora`, `debian`, or `ubuntu`
- Running kernel (`ansible_facts['kernel']`)
- `net.mptcp.enabled` and `net.ipv4.tcp_migrate_req` (`missing` when the key is absent)
- MPTCP listeners from `ss -Mlnp`, including process names when that works
- Whether the running kernel is fixed, and which check decided it

Detection order:

1. Changelog text matching `CVE-2026-98432` or `free inet_opt and ireq_opt`.
2. Distro minimum in `cve_2026_98432_check_fixed_kernels` when the changelog did not hit.
3. Upstream stable table for Fedora and for kernels that are not an EL build.
4. `unknown` when none of those apply. Ubuntu 20.04 and older are `vulnerable` unless the kernel is older than 4.4.

EL real-time kernels are not compared to the non-RT minimum. Only the RT
versions listed in `cve_2026_98432_check_fixed_kernels_rt` are used.

Missing `ss -M`, a missing changelog file, or a failed package query does not
fail the play.

## Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `cve_2026_98432_check_apply_mitigation` | `false` | Persist `net.mptcp.enabled=0` |
| `cve_2026_98432_check_disable_tcp_migrate_req` | `true` | With mitigation, also set `net.ipv4.tcp_migrate_req=0` when that key exists |
| `cve_2026_98432_check_drop_ipv4_options` | `false` | With mitigation, drop IPv4 TCP packets that carry IP options |
| `cve_2026_98432_check_firewall_backend` | `auto` | `auto`, `nftables`, `iptables`, or `none` |
| `cve_2026_98432_check_report_dir` | `""` | Controller directory for `<host>.json` |
| `cve_2026_98432_check_report_csv` | `false` | Also write `<host>.csv` |
| `cve_2026_98432_check_changelog_pattern` | CVE string or the fix subject | Changelog search |
| `cve_2026_98432_check_fixed_kernels` | See defaults | Distro minimums |
| `cve_2026_98432_check_fixed_kernels_rt` | EL 8.10 RT | Real-time minimums |
| `cve_2026_98432_check_upstream_fixed` | Upstream stable list | Fedora and non-EL fallback |
| `cve_2026_98432_check_unfixed_releases` | Ubuntu 14.04–20.04 | Releases with no published fix |

Facts after the run:

- `cve_2026_98432_check_summary` (mapping, `kernel_fixed` is JSON `null` when unknown)
- `cve_2026_98432_check_risk`
- `cve_2026_98432_check_kernel_status`

## Override the version table

Extra vars replace the whole mapping. Copy the default and change the one
release you need:

```yaml
cve_2026_98432_check_fixed_kernels:
  redhat:
    "9.8": "5.14.0-700.1.1.el9_8"
    "9": "5.14.0-700.1.1.el9_8"
  debian: {}
  ubuntu: {}
```

Quote version keys. In YAML `8.10` without quotes is not the string `8.10`.

## Tags

| Tag | Runs |
| --- | --- |
| `cve_2026_98432_check` | Full role, including mitigation when the switch is on |
| `cve_check` | Audit only |
| `report` | Gather, evaluate, and print the summary |
| `mitigate` | Mitigation tasks only. They still no-op unless the switch is true |

## Mitigation

Off by default. Turning it on is idempotent and is not a substitute for a
fixed kernel plus a reboot.

```yaml
roles:
  - role: mrjoshuap.ezcve.cve_2026_98432_check
    vars:
      cve_2026_98432_check_apply_mitigation: true
      cve_2026_98432_check_drop_ipv4_options: true
```

- `net.mptcp.enabled=0` is written to `/etc/sysctl.d/90-cve-2026-98432.conf` when the key exists.
- `net.ipv4.tcp_migrate_req=0` is set the same way when `cve_2026_98432_check_disable_tcp_migrate_req` is true.
- `auto` uses nftables when `nft` is installed, otherwise iptables.
- The nftables table `ip cve_2026_98432` drops TCP packets whose IPv4 header length is greater than 5. The role writes `/etc/nftables.d/cve_2026_98432.nft` and adds an include to `/etc/nftables.conf` or `/etc/sysconfig/nftables.conf` when that file already exists.
- The iptables rule is inserted in the `raw` `PREROUTING` chain and is not saved. It uses the `u32` match, which RHEL 9 and 10 kernels do not ship. Prefer nftables there.

Mitigation needs `ansible.posix` for the sysctl module:

```bash
ansible-galaxy collection install -r requirements.yml
```

## Reports

```yaml
cve_2026_98432_check_report_dir: /tmp/cve-2026-98432
cve_2026_98432_check_report_csv: true
```

Files are written on the controller, one host per file. A play-level
`become: true` does not change the controller write. Those tasks delegate to
localhost with `become: false`.

## Limitations

- The audit describes the running kernel. Containers report the host kernel.
- A RHEL userspace running a non-EL kernel (for example `linuxkit`) is compared
  to the upstream table, not to the EL minimum.
- Ubuntu flavor kernels other than `generic` stay `unknown` until the
  changelog names the fix or you add a rule.
- `package_facts` on RPM hosts needs the Python `rpm` bindings to list
  installed kernels for `reboot_required`. The `rpm` command used for the
  changelog does not.
- This role does not fail the host because it is vulnerable. Gate that in
  your play if you want a non-zero exit.
