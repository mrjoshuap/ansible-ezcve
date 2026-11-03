"""Version, changelog, and report helpers for the CVE-2026-98432 audit.

RPM comparison follows ``rpmvercmp`` (hyphen and dot are separators). Debian
comparison follows dpkg ``verrevcmp``. Both run on the controller so the role
does not need the rpm or apt Python modules on the target.

Galaxy and ``ansible-doc -t filter`` read one sidecar per filter name,
``plugins/filter/<name>.yml``. This file's name is not a filter name, so it
has no DOCUMENTATION string of its own.
"""

from __future__ import annotations

import base64
import re
from typing import Any

_UPSTREAM_INTRODUCED = (4, 4, 0)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


_RPI_KERNEL = re.compile(r"(?:\+rpt\b|-rpt\b|-rpi-|-(?:v6|v7l|v7|v8)\+?$)")
_RPI_NAMES = {"Raspbian", "Raspberry Pi OS", "RaspiOS"}


def cve_2026_98432_check_os_id(
    distribution: str,
    os_family: str,
    kernel: str = "",
) -> str:
    """Normalize a distribution to a supported family.

    A running release that ends in ``-pve`` is a Proxmox kernel even when
    ``/etc/os-release`` still says Debian. A Raspberry Pi kernel
    (``+rpt``, ``-rpi-``, or ``-v8+``) or a Raspbian distribution name is
    ``raspberrypi``.
    """
    release = _text(kernel)
    if release.endswith("-pve"):
        return "proxmox"
    name = _text(distribution)
    if _RPI_KERNEL.search(release) or name in _RPI_NAMES:
        return "raspberrypi"
    family = _text(os_family)
    if name == "Ubuntu":
        return "ubuntu"
    if name == "Debian":
        return "debian"
    if name == "Fedora":
        return "fedora"
    if family == "RedHat":
        return "redhat"
    return "unsupported"


def _rpm_separator(char: str) -> bool:
    return not (char.isalnum() or char in "~^")


def _strip_separators(value: str) -> str:
    index = 0
    while index < len(value) and _rpm_separator(value[index]):
        index += 1
    return value[index:]


def rpmvercmp(left: str, right: str) -> int:
    """Compare two strings the way ``rpm.vercmp`` does. Return -1, 0, or 1."""
    if left == right:
        return 0

    one = left
    two = right
    while one or two:
        one = _strip_separators(one)
        two = _strip_separators(two)

        if one[:1] == "~" or two[:1] == "~":
            if one[:1] != "~":
                return 1
            if two[:1] != "~":
                return -1
            one = one[1:]
            two = two[1:]
            continue

        if one[:1] == "^" or two[:1] == "^":
            if not one:
                return -1
            if not two:
                return 1
            if one[:1] != "^":
                return 1
            if two[:1] != "^":
                return -1
            one = one[1:]
            two = two[1:]
            continue

        if not one or not two:
            break

        numeric = one[0].isdigit()
        end_one = 0
        end_two = 0
        if numeric:
            while end_one < len(one) and one[end_one].isdigit():
                end_one += 1
            while end_two < len(two) and two[end_two].isdigit():
                end_two += 1
        else:
            while end_one < len(one) and one[end_one].isalpha():
                end_one += 1
            while end_two < len(two) and two[end_two].isalpha():
                end_two += 1

        if end_one == 0:
            return -1
        if end_two == 0:
            return 1 if numeric else -1

        seg_one = one[:end_one]
        seg_two = two[:end_two]
        one = one[end_one:]
        two = two[end_two:]
        if numeric:
            seg_one = seg_one.lstrip("0")
            seg_two = seg_two.lstrip("0")
            if len(seg_one) != len(seg_two):
                return 1 if len(seg_one) > len(seg_two) else -1
        if seg_one != seg_two:
            return 1 if seg_one > seg_two else -1

    if not one and not two:
        return 0
    if not one:
        return -1
    return 1


def cve_2026_98432_check_rpm_ge(running: str, minimum: str) -> bool:
    """Return whether ``running`` is greater than or equal to ``minimum``."""
    if not _text(running) or not _text(minimum):
        return False
    return rpmvercmp(_text(running), _text(minimum)) >= 0


def _deb_order(char: str) -> int:
    if not char:
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def deb_verrevcmp(left: str, right: str) -> int:
    """Compare Debian upstream or revision strings. Return -1, 0, or 1."""
    one = left or ""
    two = right or ""
    index_one = 0
    index_two = 0
    while index_one < len(one) or index_two < len(two):
        while (index_one < len(one) and not one[index_one].isdigit()) or (
            index_two < len(two) and not two[index_two].isdigit()
        ):
            char_one = _deb_order(one[index_one] if index_one < len(one) else "")
            char_two = _deb_order(two[index_two] if index_two < len(two) else "")
            if char_one != char_two:
                return 1 if char_one > char_two else -1
            index_one += 1
            index_two += 1
        while index_one < len(one) and one[index_one] == "0":
            index_one += 1
        while index_two < len(two) and two[index_two] == "0":
            index_two += 1
        first_diff = 0
        while (index_one < len(one) and one[index_one].isdigit()) and (
            index_two < len(two) and two[index_two].isdigit()
        ):
            if first_diff == 0 and one[index_one] != two[index_two]:
                first_diff = 1 if one[index_one] > two[index_two] else -1
            index_one += 1
            index_two += 1
        if index_one < len(one) and one[index_one].isdigit():
            return 1
        if index_two < len(two) and two[index_two].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_deb(version: str) -> tuple[int, str, str]:
    epoch = 0
    rest = version
    if ":" in rest:
        epoch_text, rest = rest.split(":", 1)
        epoch = int(epoch_text or "0")
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def deb_compare(left: str, right: str) -> int:
    """Compare two Debian package versions. Return -1, 0, or 1."""
    epoch_left, upstream_left, revision_left = _split_deb(left)
    epoch_right, upstream_right, revision_right = _split_deb(right)
    if epoch_left != epoch_right:
        return 1 if epoch_left > epoch_right else -1
    upstream = deb_verrevcmp(upstream_left, upstream_right)
    if upstream:
        return upstream
    return deb_verrevcmp(revision_left, revision_right)


def cve_2026_98432_check_deb_ge(running: str, minimum: str) -> bool:
    """Return whether a Debian package version is at least ``minimum``."""
    if not _text(running) or not _text(minimum):
        return False
    return deb_compare(_text(running), _text(minimum)) >= 0


def _string_map(mapping: Any) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        return {}
    return {_text(key): value for key, value in mapping.items()}


def _lookup_release(mapping: Any, version: str) -> Any:
    normalized = _string_map(mapping)
    text = _text(version)
    if text in normalized and normalized[text] not in ("", None, []):
        return normalized[text]
    major = text.split(".", 1)[0]
    return normalized.get(major, "")


def cve_2026_98432_check_el_minimum(
    kernel: str,
    os_version: str,
    fixed_map: dict[str, Any],
    rt_map: dict[str, Any] | None = None,
) -> str:
    """Return the EL minimum NVR for this running kernel, or an empty string."""
    match = re.search(r"\.el(\d+)", _text(kernel))
    if not match:
        return ""
    el_major = match.group(1)
    os_major = _text(os_version).split(".", 1)[0]
    lookup_version = _text(os_version) if os_major == el_major else el_major
    if ".rt" in _text(kernel):
        found = _lookup_release(rt_map or {}, lookup_version)
        return _text(found) if found else ""
    found = _lookup_release(fixed_map, lookup_version)
    if found:
        return _text(found)
    fallback = _lookup_release(fixed_map, el_major)
    return _text(fallback) if fallback else ""


def cve_2026_98432_check_kernel_flavor(kernel: str) -> str:
    """Return the Ubuntu flavor suffix, such as generic or aws."""
    parts = _text(kernel).split("-")
    if len(parts) >= 3 and parts[-1] and not parts[-1][0].isdigit():
        return parts[-1]
    return ""


def cve_2026_98432_check_deb_rule(
    package_version: str,
    kernel: str,
    os_version: str,
    rules_by_release: dict[str, Any],
) -> dict[str, Any]:
    """Return the first Debian or Ubuntu rule whose prefix and flavor match."""
    if not _text(package_version):
        return {}
    rules = _lookup_release(rules_by_release, os_version)
    if not isinstance(rules, list):
        return {}
    flavor = cve_2026_98432_check_kernel_flavor(kernel) or "generic"
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_flavor = rule.get("flavor")
        if rule_flavor and _text(rule_flavor) != flavor:
            continue
        prefix = _text(rule.get("prefix"))
        if prefix and _text(package_version).startswith(prefix):
            return rule
    return {}


def _parse_upstream(kernel: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", _text(kernel))
    if not match:
        return None
    patch = int(match.group(3) or "0")
    return int(match.group(1)), int(match.group(2)), patch


def cve_2026_98432_check_upstream_status(
    kernel: str,
    fixed_versions: list[Any],
) -> dict[str, str]:
    """Classify a mainline-style kernel against the upstream fixed stables."""
    parsed = _parse_upstream(kernel)
    if parsed is None:
        return {
            "state": "unknown",
            "detail": f"Could not parse an upstream version from {kernel}.",
        }
    if parsed < _UPSTREAM_INTRODUCED:
        return {
            "state": "not_affected",
            "detail": (
                f"{parsed[0]}.{parsed[1]}.{parsed[2]} is older than 4.4, "
                "where this bug was introduced."
            ),
        }

    branches: dict[tuple[int, int], int] = {}
    for raw in fixed_versions or []:
        version = _parse_upstream(_text(raw))
        if version is None:
            continue
        branches[(version[0], version[1])] = version[2]

    major, minor, patch = parsed
    if (major, minor) in branches:
        needed = branches[(major, minor)]
        rendered = f"{major}.{minor}.{patch}"
        floor = f"{major}.{minor}.{needed}"
        if patch >= needed:
            return {
                "state": "fixed",
                "detail": f"Upstream {rendered} is at least {floor}.",
            }
        return {
            "state": "vulnerable",
            "detail": f"Upstream {rendered} is older than {floor}.",
        }

    if (major, minor, patch) >= (7, 3, 0):
        return {
            "state": "fixed",
            "detail": (
                f"Upstream {major}.{minor}.{patch} is 7.3 or newer, "
                "which includes the fix."
            ),
        }
    return {
        "state": "vulnerable",
        "detail": (
            f"Upstream {major}.{minor} is not a fixed stable branch "
            "and is older than 7.3."
        ),
    }


def cve_2026_98432_check_upstream_minimum(
    kernel: str,
    fixed_versions: list[Any],
) -> dict[str, str]:
    """Return the same-branch floor and prefix for reboot detection."""
    parsed = _parse_upstream(kernel)
    if parsed is None:
        return {"minimum": "", "prefix": ""}
    major, minor, patch = parsed
    for raw in fixed_versions or []:
        version = _parse_upstream(_text(raw))
        if version and (version[0], version[1]) == (major, minor):
            return {
                "minimum": f"{version[0]}.{version[1]}.{version[2]}",
                "prefix": f"{major}.{minor}.",
            }
    if (major, minor, patch) >= (7, 3, 0):
        return {"minimum": "7.3", "prefix": f"{major}.{minor}."}
    return {"minimum": "", "prefix": ""}


def cve_2026_98432_check_notice(status: str) -> str:
    """Return the operator notice for a kernel status."""
    if status == "fixed":
        return (
            "The running kernel includes the fix. A kernel update does not "
            "take effect until the host reboots."
        )
    if status == "not_affected":
        return "This kernel is older than 4.4 and is not affected by CVE-2026-98432."
    if status == "vulnerable":
        return (
            "Install the distribution fixed kernel and reboot into it. "
            "Disabling MPTCP reduces one exposure and does not fix the kernel."
        )
    return (
        "The role could not decide whether the running kernel is fixed. "
        "See detection_detail."
    )


def cve_2026_98432_check_firewall_choice(
    requested: str,
    stat_results: list[dict[str, Any]],
) -> dict[str, str]:
    """Pick nftables or iptables from stat results."""
    nft = ""
    iptables = ""
    for result in stat_results or []:
        if not isinstance(result, dict) or result.get("skipped"):
            continue
        stat = result.get("stat") or {}
        if not stat.get("exists"):
            continue
        path = _text(result.get("__cve_2026_98432_check_bin"))
        if path.endswith("/nft") and not nft:
            nft = path
        if path.endswith("/iptables") and not iptables:
            iptables = path
    choice = _text(requested) or "auto"
    if choice == "nftables":
        return {"backend": "nftables" if nft else "none", "command": nft}
    if choice == "iptables":
        return {"backend": "iptables" if iptables else "none", "command": iptables}
    if choice == "none":
        return {"backend": "none", "command": ""}
    if nft:
        return {"backend": "nftables", "command": nft}
    if iptables:
        return {"backend": "iptables", "command": iptables}
    return {"backend": "none", "command": ""}


def cve_2026_98432_check_kernel_fixed(status: str) -> bool | None:
    """Map a status word to true, false, or null."""
    if status in ("fixed", "not_affected"):
        return True
    if status == "vulnerable":
        return False
    return None


def cve_2026_98432_check_build_summary(fields: dict[str, Any]) -> dict[str, Any]:
    """Add kernel_fixed and notice. kernel_fixed stays null when unknown."""
    summary = dict(fields)
    status = _text(summary.get("kernel_status"))
    summary["kernel_fixed"] = cve_2026_98432_check_kernel_fixed(status)
    summary["notice"] = cve_2026_98432_check_notice(status)
    return summary


def cve_2026_98432_check_release_unfixed(
    os_id: str,
    os_version: str,
    unfixed: dict[str, Any],
) -> bool:
    """Return whether this distro release has no published fix."""
    family = _string_map(unfixed).get(_text(os_id), [])
    if not isinstance(family, list):
        return False
    version = _text(os_version)
    for item in family:
        text = _text(item)
        if version == text or version.startswith(text + "."):
            return True
    return False


def _listen_address(line: str) -> str:
    fields = line.split()
    if len(fields) >= 4:
        return fields[3]
    return ""


def cve_2026_98432_check_ss_mptcp(result: dict[str, Any]) -> dict[str, Any]:
    """Parse ``ss -M`` output without failing when MPTCP support is absent."""
    if not isinstance(result, dict):
        return {"supported": False, "listeners": [], "error": "ss did not run"}
    if result.get("skipped"):
        return {"supported": False, "listeners": [], "error": "ss did not run"}
    stdout = _text(result.get("stdout"))
    stderr = _text(result.get("stderr"))
    rc = result.get("rc", 1)
    combined = f"{stderr}\n{stdout}".lower()
    unsupported = any(
        marker in combined
        for marker in (
            "unrecognized option",
            "invalid option",
            "unknown option",
            "operation not supported",
        )
    )
    if rc not in (0, "0"):
        message = stderr.strip() or stdout.strip() or "ss failed"
        return {"supported": False, "listeners": [], "error": message if not unsupported else message}

    listeners = []
    for line in stdout.splitlines():
        if not line.startswith("LISTEN"):
            continue
        processes = re.findall(r'users:\(\("([^"]+)"', line)
        listeners.append(
            {
                "address": _listen_address(line),
                "process": ",".join(processes),
            }
        )
    return {"supported": True, "listeners": listeners, "error": ""}


def cve_2026_98432_check_proc_value(result: dict[str, Any]) -> str:
    """Decode a slurp of a procfs sysctl, or return missing."""
    if not isinstance(result, dict):
        return "missing"
    content = result.get("content")
    if not content or result.get("failed"):
        return "missing"
    try:
        return base64.b64decode(content).decode().strip()
    except (ValueError, UnicodeError):
        return "missing"


def cve_2026_98432_check_changelog_hit(text: str, pattern: str) -> bool:
    """Return whether changelog text names the fix."""
    if not text or not pattern:
        return False
    return re.search(pattern, text) is not None


def cve_2026_98432_check_rpm_changelog(
    core_result: dict[str, Any],
    kernel_result: dict[str, Any],
    pattern: str,
) -> dict[str, Any]:
    """Use the first successful RPM changelog query."""
    pairs = (
        (core_result, "rpm changelog kernel-core"),
        (kernel_result, "rpm changelog kernel"),
    )
    for result, source in pairs:
        if not isinstance(result, dict) or result.get("skipped"):
            continue
        if result.get("rc") == 0 and result.get("stdout"):
            return {
                "checked": True,
                "hit": cve_2026_98432_check_changelog_hit(result.get("stdout", ""), pattern),
                "source": source,
            }
    return {"checked": False, "hit": False, "source": ""}


def cve_2026_98432_check_zgrep_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize a loop of ``zgrep -c`` results."""
    checked = False
    hit = False
    source = ""
    for result in results or []:
        if not isinstance(result, dict) or result.get("skipped"):
            continue
        stdout = _text(result.get("stdout")).strip()
        if result.get("rc") in (0, 1) and stdout.isdigit():
            checked = True
            stat = result.get("__cve_2026_98432_check_stat", {})
            path = ""
            if isinstance(stat, dict):
                path = _text(stat.get("__cve_2026_98432_check_path"))
            if int(stdout) > 0:
                hit = True
                source = path or source
            elif not source:
                source = path
    return {"checked": checked, "hit": hit, "source": source}


def cve_2026_98432_check_rpi_version(kernel: str) -> str:
    """Return ``major.minor.patch`` from a Raspberry Pi kernel release."""
    parsed = _parse_upstream(kernel)
    if parsed is None:
        return ""
    return f"{parsed[0]}.{parsed[1]}.{parsed[2]}"


_RPI_PACKAGE = re.compile(
    r"^(?:linux-image-rpi-.+|linux-image-.+(?:\+rpt|-rpi-|-(?:v6|v7l|v7|v8)\+?)(?:$|-.+)|raspberrypi-kernel)$"
)
_UPSTREAM_TRIPLE = re.compile(r"(?<![\d])(\d+\.\d+\.\d+)(?![\d])")


def cve_2026_98432_check_rpi_installed_versions(packages: dict[str, Any]) -> list[str]:
    """Return upstream triples of installed Raspberry Pi kernel images."""
    found: list[str] = []
    seen: set[str] = set()
    if not isinstance(packages, dict):
        return found
    for name, entries in packages.items():
        package = _text(name)
        if _RPI_PACKAGE.match(package) is None:
            continue
        candidates = [package]
        for entry in entries or []:
            if isinstance(entry, dict) and entry.get("version"):
                candidates.insert(0, _text(entry["version"]))
        triple = ""
        for candidate in candidates:
            match = _UPSTREAM_TRIPLE.search(candidate)
            if match:
                triple = match.group(1)
                break
        if triple and triple not in seen:
            seen.add(triple)
            found.append(triple)
    return found


def cve_2026_98432_check_pve_version(kernel: str) -> str:
    """Return the Proxmox ABI from ``uname -r``, without the ``-pve`` suffix."""
    text = _text(kernel)
    if text.endswith("-pve"):
        return text[: -len("-pve")]
    return ""


_PVE_PACKAGE = re.compile(r"^proxmox-kernel-.+-pve(?:-signed)?$")


def cve_2026_98432_check_pve_installed_versions(packages: dict[str, Any]) -> list[str]:
    """Return versions of installed proxmox-kernel image packages."""
    found: list[str] = []
    if not isinstance(packages, dict):
        return found
    for name, entries in packages.items():
        if _PVE_PACKAGE.match(_text(name)) is None:
            continue
        for entry in entries or []:
            if isinstance(entry, dict) and entry.get("version"):
                found.append(_text(entry["version"]))
    return found


def cve_2026_98432_check_deb_package_version(packages: dict[str, Any], kernel: str) -> str:
    """Return the package version of the running Debian or Ubuntu kernel."""
    if not isinstance(packages, dict):
        return ""
    for name in (
        f"linux-image-{kernel}",
        f"linux-image-unsigned-{kernel}",
        f"linux-modules-{kernel}",
    ):
        entries = packages.get(name) or []
        if entries and isinstance(entries[0], dict) and entries[0].get("version"):
            return _text(entries[0]["version"])
    return ""


def cve_2026_98432_check_installed_nvrs(packages: dict[str, Any], names: list[str]) -> list[str]:
    """Return installed RPM version-release strings for the given package names."""
    found: list[str] = []
    if not isinstance(packages, dict):
        return found
    for name in names:
        for entry in packages.get(name) or []:
            if not isinstance(entry, dict):
                continue
            version = _text(entry.get("version"))
            release = _text(entry.get("release"))
            if version and release:
                found.append(f"{version}-{release}")
    return found


def cve_2026_98432_check_deb_installed_versions(packages: dict[str, Any]) -> list[str]:
    """Return versions of installed linux-image packages."""
    found: list[str] = []
    if not isinstance(packages, dict):
        return found
    for name, entries in packages.items():
        if not _text(name).startswith("linux-image-"):
            continue
        for entry in entries or []:
            if isinstance(entry, dict) and entry.get("version"):
                found.append(_text(entry["version"]))
    return found


def cve_2026_98432_check_reboot_required(
    installed: list[str],
    running: str,
    minimum: str,
    kind: str,
    prefix: str = "",
) -> bool:
    """Return whether a fixed package is installed but not running."""
    if not minimum or not installed or not running:
        return False
    compare = (
        cve_2026_98432_check_rpm_ge
        if kind == "rpm"
        else cve_2026_98432_check_deb_ge
    )
    if compare(running, minimum):
        return False
    for item in installed:
        if prefix and not _text(item).startswith(prefix):
            continue
        if compare(item, minimum):
            return True
    return False


def cve_2026_98432_check_report_lines(summary: dict[str, Any]) -> list[str]:
    """Build the per-host text summary."""
    if not isinstance(summary, dict):
        return ["CVE-2026-98432 summary is missing"]
    risk = _text(summary.get("risk", "unknown")).upper()
    lines = [
        (
            f"CVE-2026-98432  host={summary.get('host')}  "
            f"risk={risk}  status={summary.get('kernel_status')}"
        ),
        (
            f"kernel={summary.get('kernel')}  "
            f"os={summary.get('os_id')} {summary.get('os_version')}"
        ),
        (
            f"detection={summary.get('detection_method')}  "
            f"{summary.get('detection_detail')}"
        ),
        (
            f"mptcp.enabled={summary.get('mptcp_enabled')}  "
            f"tcp_migrate_req={summary.get('tcp_migrate_req')}  "
            f"listeners={summary.get('mptcp_listener_count')}  "
            f"ss_mptcp={'yes' if summary.get('mptcp_ss_supported') else 'no'}"
        ),
    ]
    for listener in summary.get("mptcp_listeners") or []:
        if not isinstance(listener, dict):
            continue
        process = listener.get("process") or "unknown"
        lines.append(f"listener {listener.get('address')} process={process}")
    if summary.get("mptcp_enabled_without_listeners"):
        lines.append(
            "note: net.mptcp.enabled=1 and no MPTCP listener is open; "
            "new sockets can still appear"
        )
    if summary.get("reboot_required"):
        lines.append(
            "note: a fixed kernel package is installed and the running "
            "kernel is not that package; reboot"
        )
    if summary.get("notice"):
        lines.append(f"notice: {summary.get('notice')}")
    if summary.get("ss_error"):
        lines.append(f"ss: {summary.get('ss_error')}")
    return lines


def _csv_cell(value: Any) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = _text(value)
    if any(char in text for char in [",", '"', "\n"]):
        return '"' + text.replace('"', '""') + '"'
    return text


def cve_2026_98432_check_csv(summary: dict[str, Any]) -> str:
    """Return a one-row CSV document for the summary."""
    headers = [
        "host",
        "risk",
        "kernel_status",
        "kernel_fixed",
        "os_id",
        "os_version",
        "kernel",
        "detection_method",
        "mptcp_enabled",
        "tcp_migrate_req",
        "mptcp_listener_count",
        "mptcp_enabled_without_listeners",
        "reboot_required",
        "detection_detail",
    ]
    rows = [",".join(headers)]
    rows.append(",".join(_csv_cell(summary.get(key)) for key in headers))
    return "\n".join(rows) + "\n"


class FilterModule:
    """Ansible filter mapping."""

    def filters(self) -> dict[str, Any]:
        """Return the public filters."""
        return {
            "os_id": cve_2026_98432_check_os_id,
            "rpm_ge": cve_2026_98432_check_rpm_ge,
            "deb_ge": cve_2026_98432_check_deb_ge,
            "el_minimum": cve_2026_98432_check_el_minimum,
            "kernel_flavor": cve_2026_98432_check_kernel_flavor,
            "deb_rule": cve_2026_98432_check_deb_rule,
            "upstream_status": cve_2026_98432_check_upstream_status,
            "upstream_minimum": cve_2026_98432_check_upstream_minimum,
            "rpi_version": cve_2026_98432_check_rpi_version,
            "rpi_installed_versions": cve_2026_98432_check_rpi_installed_versions,
            "notice": cve_2026_98432_check_notice,
            "firewall_choice": cve_2026_98432_check_firewall_choice,
            "kernel_fixed": cve_2026_98432_check_kernel_fixed,
            "build_summary": cve_2026_98432_check_build_summary,
            "release_unfixed": cve_2026_98432_check_release_unfixed,
            "ss_mptcp": cve_2026_98432_check_ss_mptcp,
            "proc_value": cve_2026_98432_check_proc_value,
            "changelog_hit": cve_2026_98432_check_changelog_hit,
            "rpm_changelog": cve_2026_98432_check_rpm_changelog,
            "zgrep_summary": cve_2026_98432_check_zgrep_summary,
            "pve_version": cve_2026_98432_check_pve_version,
            "pve_installed_versions": cve_2026_98432_check_pve_installed_versions,
            "deb_package_version": cve_2026_98432_check_deb_package_version,
            "installed_nvrs": cve_2026_98432_check_installed_nvrs,
            "deb_installed_versions": cve_2026_98432_check_deb_installed_versions,
            "reboot_required": cve_2026_98432_check_reboot_required,
            "report_lines": cve_2026_98432_check_report_lines,
            "csv": cve_2026_98432_check_csv,
        }
