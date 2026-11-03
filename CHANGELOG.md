# Changelog

## 1.0.1-dev

- Release development version for 1.0.1.
- Document the collection as a series of CVE audit roles. CVE-2026-98432 is the first.
- Add a browser-only dashboard that reads per-host JSON reports in the tab.

## 1.0.0

- Role `cve_2026_98432_check` audits RHEL-family, Fedora, Debian, and Ubuntu
  hosts for CVE-2026-98432.
- Changelog text wins over the version table in `defaults/main.yml`.
- Mitigation stays off unless `cve_2026_98432_check_apply_mitigation` is true.
- Filters live in `plugins/filter/` and are called as `mrjoshuap.ezcve.*`.
- Stable releases are git tags `vX.Y.Z`. Pushes to `main` publish `{version}-dev.{timestamp}` for the next version in `galaxy.yml`. The homelab ingests stable releases through the `galaxy-requirements` sync.
