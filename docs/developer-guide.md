# Developer guide

How to run this checkout, add a CVE role, cut a Galaxy release, and publish
this site. Day-to-day use of the roles is in the [user guide](user-guide.md).
Each CVE has a page under [CVEs](cves/index.md).

## Local checkout

Filters are `mrjoshuap.ezcve.*`. The implementations share
`plugins/filter/cve_2026_98432_check.py`. Galaxy and `ansible-doc -t filter`
read `plugins/filter/<filter>.yml`, one sidecar per filter name. AAP does not
load `filter_plugins/` from a collection role. There are no modules.

Point Ansible at this checkout, then run the thin playbook:

```bash
bash scripts/link-collection.sh
ansible-playbook playbooks/cve_2026_98432_check.yml
```

`scripts/link-collection.sh` symlinks the repository to
`ansible_collections/mrjoshuap/ezcve` under `.ansible/collections` and, when
`ANSIBLE_COLLECTIONS_PATH` is set, under the first entry of that path.

## Add a CVE

Each CVE is one role. Copy the shape of `cve_2026_98432_check`. Leave
mitigation off unless that role implements a limited workaround.

1. Add `roles/cve_<year>_<id>_check/` with defaults, validation, and tasks. The role name is the variable prefix.
2. Add a thin playbook `playbooks/cve_<year>_<id>_check.yml` that calls the role.
3. Add `docs/cves/cve-<year>-<id>.md` with the fix status, variables, and limitations for that CVE.
4. Add that page under `CVEs` in `mkdocs.yml`.
5. Add a row on [the CVE overview](cves/index.md) and in the role list in `README.md`.
6. When `<role>_report_dir` is set, write one JSON object per host. Include `cve`, `host`, and `risk`. The [dashboard](dashboard.html) lists those keys with no change to `docs/dashboard.html`. `kernel_status`, `os_id`, `os_version`, `kernel`, and `reboot_required` fill the table when the role provides them. Any other keys open in the row.

## Releases

`version:` in [`galaxy.yml`](https://github.com/mrjoshuap/ansible-ezcve/blob/main/galaxy.yml)
is the next release, written as `X.Y.Z`. It has no `v` prefix and no
prerelease suffix. [`scripts/release_version.py`](https://github.com/mrjoshuap/ansible-ezcve/blob/main/scripts/release_version.py)
chooses the Galaxy version. [`.github/workflows/publish.yml`](https://github.com/mrjoshuap/ansible-ezcve/blob/main/.github/workflows/publish.yml)
builds and uploads it.

- Tag `vX.Y.Z` on the commit whose `galaxy.yml` version is `X.Y.Z`.
  GitHub Actions publishes Galaxy version `X.Y.Z`, a GitHub Release, and `mrjoshuap-ezcve-X.Y.Z.tar.gz`.
- A push to `main` that changes the collection publishes `{version}-dev.{UTC timestamp}` to Galaxy and a GitHub prerelease tagged `v{version}-dev.{timestamp}`.

```bash
git tag -a v1.0.0 -m "mrjoshuap.ezcve 1.0.0"
git push origin v1.0.0
```

After that tag, set `version:` to the following release before the next push to `main`.
Tag `v1.0.0` before changing `galaxy.yml` to `1.0.1`. The workflow refuses a
`1.0.1-dev.*` upload while Galaxy has no stable release, because that build
would satisfy `>=1.0.0`.

`>=1.0.0` stays on stable releases. `>=v1.0.0` is not a valid collection
requirement. Development builds sort before the version named in `galaxy.yml`.

Install one development build by its exact version, or the newest build of that line:

```bash
ansible-galaxy collection install 'mrjoshuap.ezcve:==1.0.0-dev.20261103142922'
ansible-galaxy collection install mrjoshuap.ezcve --pre '>=1.0.0-dev,<1.0.0'
```

`--pre` applies to the whole install. A range in `requirements.yml` does not
select pre-releases after a stable release exists. An exact `==` pin does.

The workflow uses the repository secret `GALAXY_API_KEY` (Galaxy → Preferences → API token).
The homelab ingests the stable release through the Hub remote `galaxy-requirements`,
which syncs `mrjoshuap.ezcve>=1.0.0` from Galaxy. `ee-homelab` installs that synced copy.
The job template is **Systems - Check CVE-2026-98432**.

A docs-only change does not upload a new collection. `publish.yml` ignores
`docs/` and `mkdocs.yml`. A change to `README.md` or `galaxy.yml` still
publishes, because Galaxy renders `README.md`.

## Tests

```bash
python3 tests/test_kernel_versions.py
ansible-playbook tests/version_logic.yml
ansible-lint
yamllint -c .yamllint.yml .
molecule test -s default
python3 scripts/release_version.py --self-test
```

`tests/version_logic.yml` covers Rocky/RHEL, Debian, Ubuntu, Fedora, Proxmox,
and Raspberry Pi decisions without those kernels being installed. `molecule/default` runs the
role on localhost. The lint workflow runs the same checks on every push.

## Documentation site

This site is [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).
Source pages live in `docs/`. `scripts/mkdocs_changelog.py` copies
[`CHANGELOG.md`](https://github.com/mrjoshuap/ansible-ezcve/blob/main/CHANGELOG.md)
to the changelog page at build time so the site and the repository share one
changelog. The same hook inserts the Dashboard nav item. `docs/dashboard.html`
is copied as a static file and is not rendered as Markdown, so that page can
read report JSON in the browser. A Markdown nav entry would wrap it in the
theme. The landing page reads the public GitHub Releases API for the
current stable release and the current development prerelease. `galaxy.yml`
`version:` is the next release, so the site does not display that field as
the installed version.

Preview locally from the repository root:

```bash
pip install mkdocs-material
mkdocs serve
```

[`.github/workflows/pages.yml`](https://github.com/mrjoshuap/ansible-ezcve/blob/main/.github/workflows/pages.yml)
builds the site on pushes to `main` that change `docs/`, `mkdocs.yml`,
`CHANGELOG.md`, the changelog hook, or the workflow, and on
`workflow_dispatch`.

After that workflow is on `main`, set the repository Pages source to
**GitHub Actions** once (Settings → Pages). The published site is
<https://mrjoshuap.github.io/ansible-ezcve/>.
`galaxy.yml` `documentation` and `homepage` point there.
