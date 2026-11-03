# User guide

How to install `mrjoshuap.ezcve` and run one of its CVE roles. Each role
audits a single CVE and may apply a limited mitigation. Mitigation stays off
unless that role's switch is true. The first role is
`cve_2026_98432_check`.

Fix levels, variables, and limitations are on the [CVE pages](cves/index.md).
Building and publishing the collection is in the [developer guide](developer-guide.md).

## Install

```yaml
collections:
  - name: mrjoshuap.ezcve
    version: ">=1.0.0"
```

That range stays on stable releases. Install steps also appear on the
[collection page](https://galaxy.ansible.com/ui/repo/published/mrjoshuap/ezcve/).

## Roles

Role names follow `cve_<id>_check`. Call the role by its FQCN,
`mrjoshuap.ezcve.<role>`.

| Role | Page |
| --- | --- |
| `cve_2026_98432_check` | [CVE-2026-98432](cves/cve-2026-98432.md) |

A default run changes nothing. The role prints a text summary and sets a fact
named `<role>_summary`. `become` is required when the role reads process
names. Changelog reads and sysctl reads for CVE-2026-98432 do not need it.
If privilege escalation fails, that role lists listeners without process names.

## Audit

```yaml
- name: Audit hosts for CVE-2026-98432
  hosts: all
  gather_facts: true
  become: true
  roles:
    - role: mrjoshuap.ezcve.cve_2026_98432_check
```

The next CVE role uses the same play shape. Swap the role name.

## Reports

Set `<role>_report_dir` to a directory on the controller. The role writes
`<directory>/<inventory_hostname>.json`, one summary object per host. An
empty string skips the files. A play-level `become: true` does not change the
controller write. Those tasks delegate to localhost with `become: false`.

For the first role:

```yaml
cve_2026_98432_check_report_dir: ./cve-reports
cve_2026_98432_check_report_csv: false
```

`cve_2026_98432_check_report_csv` also writes `<host>.csv`. The
[dashboard](dashboard.html) reads the JSON files and ignores CSV.

Open the dashboard and choose the JSON files or the report folder. The page
reads them with the FileReader API in that tab. It does not upload them.

Use a separate directory for each role. Two roles that share a directory and
the same inventory hostname overwrite `<hostname>.json`. The dashboard can
load several directories in one selection. The same `cve` and `host` loaded
twice keeps the later file.

The summary object includes `cve`, `host`, and `risk`. CVE-2026-98432 also
records kernel status, listeners, and whether a reboot is required. Process
names from `ss -Mlnp` can appear in the file.

## Mitigation

Off by default. Turning it on is idempotent and is not a substitute for the
vendor fix. What a role changes is on that CVE's page. The
[CVE-2026-98432 page](cves/cve-2026-98432.md) covers sysctl, nftables, and
iptables for the first role.
