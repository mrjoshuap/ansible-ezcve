"""Unit tests for CVE-2026-98432 version and report helpers."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "filter"
    / "cve_2026_98432_check.py"
)
SPEC = importlib.util.spec_from_file_location("cve_2026_98432_check", MODULE_PATH)
assert SPEC and SPEC.loader
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)


def rpm_vercmp(left: str, right: str) -> int:
    """Ask the system rpm binary for its vercmp result."""
    expression = '%%{lua:print(rpm.vercmp("%s", "%s"))}' % (left, right)
    completed = subprocess.run(
        ["rpm", "--eval", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(completed.stdout.strip())


def test_rpm_matches_system_vercmp() -> None:
    try:
        rpm_probe = subprocess.run(["rpm", "--version"], capture_output=True)
    except OSError:
        print("skip rpm parity: rpm is not installed")
        return
    if rpm_probe.returncode != 0:
        print("skip rpm parity: rpm is not installed")
        return
    pairs = [
        ("1.0", "1.0"),
        ("1.0", "1.1"),
        ("1.1", "1.0"),
        ("1.0+git", "1.0"),
        ("1.0~rc1", "1.0"),
        ("1.0^2020", "1.0"),
        ("2.0", "2"),
        ("1", "01"),
        ("687.64.1.el9_8.x86_64", "687.64.1.el9_8"),
        ("553.100.1.el8_10", "553.182.1.el8_10"),
        ("553.182.1.rt7.523.el8_10", "553.182.1.el8_10"),
        ("553.182.1.rt7.1.el8_10", "553.182.1.el8_10"),
        ("5.14.0-687.64.1.el9_8.x86_64", "5.14.0-687.64.1.el9_8"),
        ("5.14.0-687.64.0.el9_8.x86_64", "5.14.0-687.64.1.el9_8"),
        ("4.18.0-553.182.1.el8_10", "4.18.0-553.182.1.el8_10"),
        ("4.18.0-477.178.1.el8_8", "4.18.0-553.182.1.el8_10"),
        ("4.18.0-477.178.1.el8_8", "4.18.0-477.178.1.el8_8"),
        ("4.18.0-477.178.0.el8_8", "4.18.0-477.178.1.el8_8"),
        ("6.12.0-211.72.1.el10_2", "6.12.0-55.117.1.el10_0"),
        ("6.12.0-55.117.1.el10_0", "6.12.0-55.117.1.el10_0"),
        ("7.0.14-linuxkit", "5.14.0-687.64.1.el9_8"),
        ("4.18.0-553.182.1.rt7.523.el8_10", "4.18.0-553.182.1.rt7.523.el8_10"),
    ]
    for left, right in pairs:
        expected = rpm_vercmp(left, right)
        actual = HELPERS.rpmvercmp(left, right)
        assert actual == expected, f"{left!r} vs {right!r}: {actual} != {expected}"


def test_debian_versions() -> None:
    assert HELPERS.deb_compare("6.1.190-1", "6.1.190-1") == 0
    assert HELPERS.deb_compare("6.1.189-1", "6.1.190-1") < 0
    assert HELPERS.deb_compare("6.1.191-1", "6.1.190-1") > 0
    assert HELPERS.deb_compare("6.12.113-1~deb12u1", "6.12.113-1") < 0
    assert HELPERS.deb_compare("6.12.113-1~deb12u1", "6.12.112-1") > 0
    assert HELPERS.deb_compare("6.12.113-1~deb12u1", "6.12.113-1~deb12u1") == 0
    assert HELPERS.deb_compare("6.8.0-149.148", "6.8.0-149.149") < 0
    assert HELPERS.deb_compare("6.8.0-149.149", "6.8.0-149.149") == 0
    assert HELPERS.deb_compare("6.8.0-149.149~22.04.1", "6.8.0-149.149") < 0
    assert HELPERS.deb_compare("6.8.0-149.149~22.04.1", "6.8.0-148.148") > 0
    assert HELPERS.deb_compare("7.3.0-10.9", "7.3.0-10.10") < 0
    assert HELPERS.deb_compare("7.3.0-10.10", "7.3.0-10.10") == 0
    assert HELPERS.deb_compare("7.3.0-11.11", "7.3.0-10.10") > 0
    assert HELPERS.deb_compare("5.15.0-202.212", "5.15.0-203.213") < 0
    assert HELPERS.deb_compare("5.15.0-203.213", "5.15.0-203.213") == 0
    assert HELPERS.deb_compare("1:6.1.190-1", "6.1.190-1") > 0
    assert HELPERS.deb_compare("0:6.1.190-1", "6.1.190-1") == 0


def test_upstream_status() -> None:
    fixed = [
        "5.10.272",
        "5.15.223",
        "6.1.190",
        "6.6.159",
        "6.12.113",
        "6.18.56",
        "7.2.10",
        "7.3",
    ]
    status = HELPERS.cve_2026_98432_check_upstream_status
    assert status("3.10.0-1160.el7.x86_64", fixed)["state"] == "not_affected"
    assert status("6.12.113-200.fc42.x86_64", fixed)["state"] == "fixed"
    assert status("6.12.100-200.fc42.x86_64", fixed)["state"] == "vulnerable"
    assert status("7.0.14-linuxkit", fixed)["state"] == "vulnerable"
    assert status("7.3.0-10-generic", fixed)["state"] == "fixed"
    assert status("7.2.9", fixed)["state"] == "vulnerable"
    assert status("7.2.10", fixed)["state"] == "fixed"
    assert status("6.8.0-45-generic", fixed)["state"] == "vulnerable"


def test_el_minimum_uses_minor_and_skips_non_el() -> None:
    fixed = {
        "8.8": "4.18.0-477.178.1.el8_8",
        "8.10": "4.18.0-553.182.1.el8_10",
        "8": "4.18.0-553.182.1.el8_10",
        "9.8": "5.14.0-687.64.1.el9_8",
        "9": "5.14.0-687.64.1.el9_8",
    }
    rt = {"8.10": "4.18.0-553.182.1.rt7.523.el8_10"}
    minimum = HELPERS.cve_2026_98432_check_el_minimum
    assert (
        minimum("4.18.0-477.178.1.el8_8.x86_64", "8.8", fixed, rt)
        == "4.18.0-477.178.1.el8_8"
    )
    assert (
        minimum("5.14.0-611.5.1.el9_8.x86_64", "9.8", fixed, rt)
        == "5.14.0-687.64.1.el9_8"
    )
    assert minimum("7.0.14-linuxkit", "9.8", fixed, rt) == ""
    assert (
        minimum("4.18.0-553.182.1.rt7.523.el8_10.x86_64", "8.10", fixed, rt)
        == "4.18.0-553.182.1.rt7.523.el8_10"
    )
    assert minimum("5.14.0-687.64.1.rt1.el9_8.x86_64", "9.8", fixed, rt) == ""


def test_ubuntu_rule_is_flavor_specific() -> None:
    rules = {
        "24.04": [
            {
                "flavor": "generic",
                "prefix": "6.8.0-",
                "minimum": "6.8.0-149.149",
                "pocket": "proposed",
            }
        ]
    }
    rule = HELPERS.cve_2026_98432_check_deb_rule
    generic = rule("6.8.0-45.45", "6.8.0-45-generic", "24.04", rules)
    assert generic["minimum"] == "6.8.0-149.149"
    assert rule("6.8.0-1069.74", "6.8.0-1069-aws", "24.04", rules) == {}


def test_ss_parser() -> None:
    parsed = HELPERS.cve_2026_98432_check_ss_mptcp(
        {
            "rc": 0,
            "stdout": (
                "State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
                'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=3))\n'
            ),
            "stderr": "",
        }
    )
    assert parsed["supported"] is True
    assert parsed["listeners"] == [{"address": "0.0.0.0:443", "process": "nginx"}]
    unsupported = HELPERS.cve_2026_98432_check_ss_mptcp(
        {"rc": 1, "stdout": "", "stderr": "ss: unrecognized option: M"}
    )
    assert unsupported["supported"] is False
    assert unsupported["listeners"] == []


def test_pve_kernel_abi() -> None:
    version = HELPERS.cve_2026_98432_check_pve_version
    assert version("7.0.14-25-pve") == "7.0.14-25"
    assert version("6.8.12-9-pve") == "6.8.12-9"
    assert version("7.0.14-25-pve-signed") == ""
    assert version("6.12.113-amd64") == ""
    assert HELPERS.cve_2026_98432_check_deb_ge("7.0.14-25", "7.0.14-25")
    assert HELPERS.cve_2026_98432_check_deb_ge("7.0.14-26", "7.0.14-25")
    assert not HELPERS.cve_2026_98432_check_deb_ge("7.0.14-24", "7.0.14-25")
    assert not HELPERS.cve_2026_98432_check_deb_ge("7.0.2-6", "7.0.14-25")
    assert not HELPERS.cve_2026_98432_check_deb_ge("6.8.12-30", "7.0.14-25")
    assert not HELPERS.cve_2026_98432_check_deb_ge("6.17.13-9", "7.0.14-25")
    assert not HELPERS.cve_2026_98432_check_deb_ge("6.14.11-9", "7.0.14-25")
    packages = {
        "proxmox-kernel-7.0.14-25-pve-signed": [{"version": "7.0.14-25"}],
        "proxmox-kernel-7.0.14-24-pve": [{"version": "7.0.14-24"}],
        "proxmox-kernel-helper": [{"version": "8.1.0"}],
        "linux-image-6.12.113-amd64": [{"version": "6.12.113-1"}],
    }
    found = HELPERS.cve_2026_98432_check_pve_installed_versions(packages)
    assert found == ["7.0.14-25", "7.0.14-24"]
    assert HELPERS.cve_2026_98432_check_reboot_required(
        found,
        "7.0.14-24",
        "7.0.14-25",
        "deb",
    )
    assert not HELPERS.cve_2026_98432_check_reboot_required(
        found,
        "7.0.14-25",
        "7.0.14-25",
        "deb",
    )


def test_rpi_kernel_uses_upstream_floors() -> None:
    floors = [
        "5.10.272",
        "5.15.223",
        "6.1.190",
        "6.6.159",
        "6.12.113",
        "6.18.56",
        "7.2.10",
        "7.3",
    ]
    status = HELPERS.cve_2026_98432_check_upstream_status
    assert status("6.18.50+rpt-rpi-v8", floors)["state"] == "vulnerable"
    assert status("6.18.59+rpt-rpi-v8", floors)["state"] == "fixed"
    assert status("6.18.59-v8+", floors)["state"] == "fixed"
    assert status("6.12.113+rpt-rpi-2712", floors)["state"] == "fixed"
    assert status("6.12.100+rpt-rpi-2712", floors)["state"] == "vulnerable"
    assert status("6.1.190-v8+", floors)["state"] == "fixed"
    assert status("6.1.21-v7l+", floors)["state"] == "vulnerable"
    minimum = HELPERS.cve_2026_98432_check_upstream_minimum
    assert minimum("6.18.50+rpt-rpi-v8", floors) == {
        "minimum": "6.18.56",
        "prefix": "6.18.",
    }
    assert minimum("6.12.100+rpt-rpi-2712", floors)["minimum"] == "6.12.113"
    assert HELPERS.cve_2026_98432_check_rpi_version("6.18.50+rpt-rpi-v8") == "6.18.50"
    packages = {
        "linux-image-rpi-v8": [{"version": "1:6.18.59-1+rpt1"}],
        "linux-image-6.18.50+rpt-rpi-v8": [{"version": "1:6.18.50-1+rpt1"}],
        "linux-image-6.12.113-arm64": [{"version": "6.12.113-1"}],
        "raspberrypi-kernel": [{"version": "1:1.20230405-1"}],
    }
    found = HELPERS.cve_2026_98432_check_rpi_installed_versions(packages)
    assert found == ["6.18.59", "6.18.50"]
    assert HELPERS.cve_2026_98432_check_reboot_required(
        found,
        "6.18.50",
        "6.18.56",
        "deb",
        "6.18.",
    )
    assert not HELPERS.cve_2026_98432_check_reboot_required(
        ["6.12.113"],
        "6.18.50",
        "6.18.56",
        "deb",
        "6.18.",
    )


def test_os_id_treats_pve_kernel_as_proxmox() -> None:
    os_id = HELPERS.cve_2026_98432_check_os_id
    assert os_id("Debian", "Debian", "7.0.14-25-pve") == "proxmox"
    assert os_id("Debian", "Debian", "6.8.12-9-pve") == "proxmox"
    assert os_id("Debian", "Debian", "6.12.113-amd64") == "debian"
    assert os_id("Ubuntu", "Debian") == "ubuntu"
    assert os_id("Rocky", "RedHat", "5.14.0-687.64.1.el9_8.x86_64") == "redhat"
    assert os_id("Fedora", "RedHat", "6.12.113-200.fc42.x86_64") == "fedora"
    assert os_id("Debian", "Debian", "6.18.50+rpt-rpi-v8") == "raspberrypi"
    assert os_id("Debian", "Debian", "6.1.21-v8+") == "raspberrypi"
    assert os_id("Raspbian", "Debian", "6.18.59") == "raspberrypi"
    assert os_id("Debian", "Debian", "6.12.113-arm64") == "debian"


def test_reboot_required_for_older_running_kernel() -> None:
    assert HELPERS.cve_2026_98432_check_reboot_required(
        ["5.14.0-687.64.1.el9_8", "5.14.0-611.5.1.el9_8"],
        "5.14.0-611.5.1.el9_8.x86_64",
        "5.14.0-687.64.1.el9_8",
        "rpm",
    )
    assert not HELPERS.cve_2026_98432_check_reboot_required(
        ["5.14.0-687.64.1.el9_8"],
        "5.14.0-687.64.1.el9_8.x86_64",
        "5.14.0-687.64.1.el9_8",
        "rpm",
    )


def main() -> None:
    test_rpm_matches_system_vercmp()
    test_debian_versions()
    test_upstream_status()
    test_el_minimum_uses_minor_and_skips_non_el()
    test_ubuntu_rule_is_flavor_specific()
    test_ss_parser()
    test_pve_kernel_abi()
    test_rpi_kernel_uses_upstream_floors()
    test_os_id_treats_pve_kernel_as_proxmox()
    test_reboot_required_for_older_running_kernel()
    print("ok")


if __name__ == "__main__":
    main()
