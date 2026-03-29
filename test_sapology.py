"""
Unit tests for SAPology.py

Run with:
    python -m pytest test_sapology.py -v
  or:
    python -m unittest test_sapology -v
"""
import sys
import os
import struct
import socket
import unittest
from unittest.mock import MagicMock, patch, Mock, call

# ---------------------------------------------------------------------------
# Bootstrap — add the SAPology directory to sys.path so we can import the
# module directly without installing it as a package.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SAPology
from SAPology import (
    # Data model
    Severity, Finding, SAPInstance, SAPSystem,
    # Pure helpers
    parse_instance_range, build_port_list, deduce_instance,
    extract_ascii_strings,
    # Version-only CVE checks (pure — no network)
    check_cve_2021_21475, check_cve_2021_21482,
    # DIAG info-leak check (takes SAPInstance, no network)
    check_diag_login_info_leak,
    # Network CVE checks (will be mocked)
    check_cve_2025_31324, check_cve_2022_41272,
    # Constants
    SAP_PORTS, SAP_FIXED_PORTS, NON_SAP_PORTS,
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Data model
# ═══════════════════════════════════════════════════════════════════════════

class TestSeverity(unittest.TestCase):
    def test_order(self):
        """CRITICAL is numerically lowest (highest priority)."""
        self.assertLess(Severity.CRITICAL, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.LOW)
        self.assertLess(Severity.LOW, Severity.INFO)


class TestFinding(unittest.TestCase):
    def _make(self, **kwargs):
        defaults = dict(name="Test", severity=Severity.HIGH,
                        description="desc", remediation="fix",
                        detail="detail", port=8000)
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_basic_construction(self):
        f = self._make(name="CVE-1234", port=3200)
        self.assertEqual(f.name, "CVE-1234")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.port, 3200)

    def test_optional_fields_default(self):
        f = Finding(name="x", severity=Severity.LOW, description="d")
        self.assertEqual(f.remediation, "")
        self.assertEqual(f.detail, "")
        self.assertEqual(f.port, 0)

    def test_to_dict_keys(self):
        f = self._make()
        d = f.to_dict()
        for key in ("name", "severity", "description", "remediation", "detail", "port"):
            self.assertIn(key, d)

    def test_severity_in_dict_is_string(self):
        f = self._make(severity=Severity.CRITICAL)
        d = f.to_dict()
        self.assertIsInstance(d["severity"], str)
        self.assertEqual(d["severity"].upper(), "CRITICAL")


class TestSAPInstance(unittest.TestCase):
    def test_defaults(self):
        inst = SAPInstance(host="server", ip="10.0.0.1", instance_nr="00")
        self.assertEqual(inst.ports, {})
        self.assertEqual(inst.services, {})
        self.assertEqual(inst.findings, [])

    def test_to_dict(self):
        inst = SAPInstance(host="h", ip="1.2.3.4", instance_nr="05",
                           ports={3205: "SAP Dispatcher (DIAG)"})
        d = inst.to_dict()
        self.assertEqual(d["ip"], "1.2.3.4")
        self.assertIn("3205", str(d["ports"]))


class TestSAPSystem(unittest.TestCase):
    def _make_system(self, *severities):
        """Helper: build a SAPSystem with one Finding per severity."""
        sys_obj = SAPSystem(sid="TST")
        for sev in severities:
            inst = SAPInstance(host="h", ip="10.0.0.1", instance_nr="00")
            inst.findings.append(
                Finding(name="f", severity=sev, description="d")
            )
            sys_obj.instances.append(inst)
        return sys_obj

    def test_default_sid(self):
        s = SAPSystem()
        self.assertEqual(s.sid, "UNKNOWN")

    def test_highest_severity_critical(self):
        s = self._make_system(Severity.HIGH, Severity.CRITICAL, Severity.INFO)
        self.assertEqual(s.highest_severity(), Severity.CRITICAL)

    def test_highest_severity_no_findings(self):
        s = SAPSystem(sid="X")
        self.assertIsNone(s.highest_severity())

    def test_all_findings_aggregates(self):
        s = SAPSystem(sid="X")
        for i in range(3):
            inst = SAPInstance(host="h", ip="10.0.0.1", instance_nr="%02d" % i)
            inst.findings.append(Finding(name="f%d" % i, severity=Severity.LOW,
                                         description="d"))
            s.instances.append(inst)
        self.assertEqual(len(s.all_findings()), 3)


# ═══════════════════════════════════════════════════════════════════════════
# 2. parse_instance_range
# ═══════════════════════════════════════════════════════════════════════════

class TestParseInstanceRange(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(parse_instance_range("00"), [0])
        self.assertEqual(parse_instance_range("05"), [5])
        self.assertEqual(parse_instance_range("99"), [99])

    def test_range(self):
        self.assertEqual(parse_instance_range("00-03"), [0, 1, 2, 3])
        self.assertEqual(parse_instance_range("10-12"), [10, 11, 12])

    def test_comma_list(self):
        self.assertEqual(parse_instance_range("00,05,10"), [0, 5, 10])

    def test_mixed_range_and_values(self):
        result = parse_instance_range("00-02,10,20-21")
        self.assertEqual(result, [0, 1, 2, 10, 20, 21])

    def test_deduplication(self):
        result = parse_instance_range("00,00,01")
        self.assertEqual(result, [0, 1])

    def test_sorted_output(self):
        result = parse_instance_range("10,00,05")
        self.assertEqual(result, sorted(result))

    def test_clamped_to_99(self):
        result = parse_instance_range("98-101")
        self.assertEqual(result, [98, 99])

    def test_whitespace_tolerance(self):
        result = parse_instance_range("00, 01, 02")
        self.assertEqual(result, [0, 1, 2])


# ═══════════════════════════════════════════════════════════════════════════
# 3. deduce_instance
# ═══════════════════════════════════════════════════════════════════════════

class TestDeduceInstance(unittest.TestCase):
    def test_dispatcher_range(self):
        self.assertEqual(deduce_instance(3200), "00")
        self.assertEqual(deduce_instance(3215), "15")
        # 3299 is SAP Router (fixed port) so returns XX; use 3298 for instance 98
        self.assertEqual(deduce_instance(3298), "98")

    def test_gateway_range(self):
        self.assertEqual(deduce_instance(3300), "00")
        self.assertEqual(deduce_instance(3301), "01")

    def test_ms_internal_range(self):
        self.assertEqual(deduce_instance(3900), "00")
        self.assertEqual(deduce_instance(3910), "10")

    def test_icm_http_range(self):
        self.assertEqual(deduce_instance(8000), "00")
        self.assertEqual(deduce_instance(8001), "01")

    def test_icm_https_range(self):
        self.assertEqual(deduce_instance(4300), "00")
        self.assertEqual(deduce_instance(4301), "01")

    def test_ms_http_range(self):
        self.assertEqual(deduce_instance(8100), "00")
        self.assertEqual(deduce_instance(8102), "02")

    def test_j2ee_range(self):
        self.assertEqual(deduce_instance(50000), "00")
        self.assertEqual(deduce_instance(50100), "01")
        self.assertEqual(deduce_instance(50200), "02")

    def test_sapcontrol_port(self):
        # 50013 = instance 00
        self.assertEqual(deduce_instance(50013), "00")
        # 50113 = instance 01
        self.assertEqual(deduce_instance(50113), "01")

    def test_fixed_ports_return_xx(self):
        for port in SAP_FIXED_PORTS:
            self.assertEqual(deduce_instance(port), "XX",
                             msg="Fixed port %d should return XX" % port)

    def test_non_sap_ports_return_xx(self):
        for port in NON_SAP_PORTS:
            self.assertEqual(deduce_instance(port), "XX")

    def test_unknown_port_returns_xx(self):
        self.assertEqual(deduce_instance(9999), "XX")
        self.assertEqual(deduce_instance(1234), "XX")


# ═══════════════════════════════════════════════════════════════════════════
# 4. build_port_list
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildPortList(unittest.TestCase):
    def test_returns_list_of_tuples(self):
        result = build_port_list([0])
        self.assertIsInstance(result, list)
        self.assertTrue(all(len(t) == 4 for t in result))

    def test_instance_00_dispatcher(self):
        ports = [t[0] for t in build_port_list([0])]
        self.assertIn(3200, ports)  # dispatcher instance 00

    def test_instance_00_gateway(self):
        ports = [t[0] for t in build_port_list([0])]
        self.assertIn(3300, ports)  # gateway instance 00

    def test_instance_01_ports(self):
        ports = [t[0] for t in build_port_list([1])]
        self.assertIn(3201, ports)  # dispatcher instance 01
        self.assertIn(3301, ports)  # gateway instance 01

    def test_no_non_sap_ports(self):
        ports = set(t[0] for t in build_port_list(list(range(100))))
        for bad_port in NON_SAP_PORTS:
            self.assertNotIn(bad_port, ports,
                             msg="NON_SAP port %d should be excluded" % bad_port)

    def test_quick_mode_only_key_ports(self):
        full = set(t[0] for t in build_port_list([0], quick=False))
        quick = set(t[0] for t in build_port_list([0], quick=True))
        # Quick is a strict subset of full
        self.assertTrue(quick.issubset(full),
                        msg="Quick mode ports should be a subset of full mode")
        # Quick mode is smaller
        self.assertLess(len(quick), len(full))

    def test_quick_mode_contains_dispatcher_and_gateway(self):
        quick = set(t[0] for t in build_port_list([0], quick=True))
        self.assertIn(3200, quick)  # dispatcher
        self.assertIn(3300, quick)  # gateway

    def test_full_mode_contains_fixed_ports(self):
        full = set(t[0] for t in build_port_list([0], quick=False))
        for port in SAP_FIXED_PORTS:
            self.assertIn(port, full,
                          msg="Fixed port %d should be in full port list" % port)

    def test_hana_sql_ports_in_full_mode(self):
        full = set(t[0] for t in build_port_list([0]))
        self.assertIn(30013, full)  # HANA SystemDB instance 00
        self.assertIn(30015, full)  # HANA Tenant instance 00

    def test_multiple_instances(self):
        result = build_port_list([0, 1, 2])
        ports = [t[0] for t in result]
        self.assertIn(3200, ports)
        self.assertIn(3201, ports)
        self.assertIn(3202, ports)

    def test_empty_instances(self):
        result = build_port_list([])
        # Only fixed ports remain
        self.assertTrue(len(result) > 0)
        ports = set(t[0] for t in result)
        for fixed in SAP_FIXED_PORTS:
            self.assertIn(fixed, ports)


# ═══════════════════════════════════════════════════════════════════════════
# 5. extract_ascii_strings
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractAsciiStrings(unittest.TestCase):
    def test_plain_ascii(self):
        data = b"hello world"
        result = extract_ascii_strings(data, min_len=3)
        self.assertIn("hello world", result)

    def test_min_len_filter(self):
        data = b"ab\x00hello\x00xy"
        result = extract_ascii_strings(data, min_len=4)
        self.assertNotIn("ab", result)
        self.assertIn("hello", result)

    def test_binary_separator(self):
        data = b"ABC\x00\xff\xfeDEFGH"
        result = extract_ascii_strings(data, min_len=3)
        self.assertIn("ABC", result)
        self.assertIn("DEFGH", result)

    def test_empty_data(self):
        self.assertEqual(extract_ascii_strings(b"", min_len=3), [])

    def test_all_binary(self):
        data = bytes(range(128, 256))
        self.assertEqual(extract_ascii_strings(data, min_len=3), [])


# ═══════════════════════════════════════════════════════════════════════════
# 6. CVE-2021-21475 (MDM version check — pure)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckCve202121475(unittest.TestCase):
    """check_cve_2021_21475 parses a version string and returns Finding or None."""

    def test_empty_string_returns_none(self):
        self.assertIsNone(check_cve_2021_21475(""))

    def test_none_returns_none(self):
        self.assertIsNone(check_cve_2021_21475(None))

    def test_non_71_version_not_affected(self):
        # MDM 7.2 is not in scope
        self.assertIsNone(check_cve_2021_21475("Version 7.2 (7.2.5.100 Win64)"))

    def test_old_sp_is_vulnerable(self):
        # SP 15 < 16 → vulnerable
        f = check_cve_2021_21475("Version 7.1 (7.1.15.999 Win64)")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.HIGH)

    def test_sp16_below_fix_is_vulnerable(self):
        # SP16, patch 16 < required 17 → vulnerable
        f = check_cve_2021_21475("Version 7.1 (7.1.16.16 Win64)")
        self.assertIsNotNone(f)

    def test_sp16_at_fix_is_safe(self):
        # SP16, patch 17 >= required 17 → safe
        self.assertIsNone(check_cve_2021_21475("Version 7.1 (7.1.16.17 Win64)"))

    def test_sp17_below_fix_is_vulnerable(self):
        f = check_cve_2021_21475("Version 7.1 (7.1.17.13 Win64)")
        self.assertIsNotNone(f)

    def test_sp17_at_fix_is_safe(self):
        self.assertIsNone(check_cve_2021_21475("Version 7.1 (7.1.17.14 Win64)"))

    def test_sp21_is_safe(self):
        # SP 21+ is fully patched
        self.assertIsNone(check_cve_2021_21475("Version 7.1 (7.1.21.0 Win64)"))

    def test_finding_has_correct_port(self):
        f = check_cve_2021_21475("Version 7.1 (7.1.15.0 Win64)")
        self.assertIsNotNone(f)
        self.assertEqual(f.port, 59950)


# ═══════════════════════════════════════════════════════════════════════════
# 7. CVE-2021-21482 (MDM version check — pure)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckCve202121482(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(check_cve_2021_21482(""))

    def test_non_71_not_affected(self):
        self.assertIsNone(check_cve_2021_21482("Version 7.2 (7.2.5.100 Win64)"))

    def test_sp_below_20_is_vulnerable(self):
        f = check_cve_2021_21482("Version 7.1 (7.1.19.999 Win64)")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_sp20_below_fix_is_vulnerable(self):
        # SP20, patch 7 < required 8
        f = check_cve_2021_21482("Version 7.1 (7.1.20.7 Win64)")
        self.assertIsNotNone(f)

    def test_sp20_at_fix_is_safe(self):
        self.assertIsNone(check_cve_2021_21482("Version 7.1 (7.1.20.8 Win64)"))

    def test_sp21_is_safe(self):
        self.assertIsNone(check_cve_2021_21482("Version 7.1 (7.1.21.0 Win64)"))


# ═══════════════════════════════════════════════════════════════════════════
# 8. check_diag_login_info_leak (takes SAPInstance — no network)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckDiagLoginInfoLeak(unittest.TestCase):
    def _make_inst(self, diag_info=None):
        inst = SAPInstance(host="h", ip="10.0.0.1", instance_nr="00")
        inst.services["dispatcher"] = {"port": 3200}
        if diag_info:
            for k, v in diag_info.items():
                inst.info["diag_%s" % k] = v
        return inst

    def test_no_screen_info_returns_none(self):
        inst = self._make_inst({"DBNAME": "PRD"})
        self.assertIsNone(check_diag_login_info_leak(inst))

    def test_with_screen_info_returns_finding(self):
        inst = self._make_inst({"SCREEN_INFO": "SAP", "DBNAME": "PRD"})
        f = check_diag_login_info_leak(inst)
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.INFO)

    def test_finding_port_matches_dispatcher(self):
        inst = self._make_inst({"SCREEN_INFO": "SAP"})
        inst.services["dispatcher"] = {"port": 3205}
        f = check_diag_login_info_leak(inst)
        self.assertEqual(f.port, 3205)

    def test_finding_contains_diag_fields_in_detail(self):
        inst = self._make_inst({"SCREEN_INFO": "SAP R/3", "DBNAME": "PRD"})
        f = check_diag_login_info_leak(inst)
        self.assertIn("PRD", f.detail)


# ═══════════════════════════════════════════════════════════════════════════
# 9. Non-SSL HTTP finding logic
#    The logic lives inside assess_vulnerabilities. We test it by constructing
#    a minimal SAPInstance and SAPSystem, patching away all network calls,
#    and checking the finding is (or is not) created.
# ═══════════════════════════════════════════════════════════════════════════

# All network-dependent check functions called by assess_vulnerabilities
_NETWORK_CHECKS = [
    "SAPology.check_gw_sapxpg",
    "SAPology.check_gw_monitor_open",
    "SAPology.check_ms_internal_open",
    "SAPology.check_ms_acl",
    "SAPology.check_cve_2020_6287",
    "SAPology.check_cve_2025_31324",
    "SAPology.check_cve_2022_22536",
    "SAPology.check_cve_2020_6207",
    "SAPology.check_cve_2010_5326",
    "SAPology.check_cve_2021_33690",
    "SAPology.check_cve_2020_6308",
    "SAPology.check_bo_cmc_exposed",
    "SAPology.check_cve_2024_41730",
    "SAPology.check_cve_2025_0061",
    "SAPology.check_bo_cms_network_exposed",
    "SAPology.check_icm_info_leak",
    "SAPology.check_sapcontrol_unprotected",
    "SAPology.check_diag_login_info_leak",
    "SAPology.check_cve_2022_41272",
    "SAPology.check_weak_ssl",
    "SAPology.check_cve_2021_21475",
    "SAPology.check_cve_2021_21482",
]


def _patch_all_network(test_fn):
    """Decorator: patch every network check to return None."""
    for target in reversed(_NETWORK_CHECKS):
        test_fn = patch(target, return_value=None)(test_fn)
    return test_fn


class TestNonSslHttpFinding(unittest.TestCase):
    """Tests for the 'Unencrypted SAP HTTP Service Exposed' HIGH finding."""

    def _run_assess(self, inst):
        """Run assess_vulnerabilities on a single-instance landscape."""
        sys_obj = SAPSystem(sid="TST", system_type="ABAP")
        sys_obj.instances.append(inst)
        SAPology.assess_vulnerabilities([sys_obj], timeout=1)
        return inst.findings

    def _make_inst_with_ports(self, ports_dict):
        inst = SAPInstance(host="h", ip="10.0.0.1", instance_nr="00")
        inst.ports = ports_dict
        return inst

    @_patch_all_network
    def test_icm_http_triggers_finding(self, *mocks):
        inst = self._make_inst_with_ports({8000: "ICM HTTP"})
        findings = self._run_assess(inst)
        names = [f.name for f in findings]
        self.assertIn("Unencrypted SAP HTTP Service Exposed", names)

    @_patch_all_network
    def test_icm_https_does_not_trigger(self, *mocks):
        inst = self._make_inst_with_ports({4300: "ICM HTTPS"})
        findings = self._run_assess(inst)
        names = [f.name for f in findings]
        self.assertNotIn("Unencrypted SAP HTTP Service Exposed", names)

    @_patch_all_network
    def test_multiple_http_ports_single_finding(self, *mocks):
        inst = self._make_inst_with_ports({
            8000: "ICM HTTP",
            50013: "SAPControl SOAP (HTTP)",
            50000: "J2EE HTTP",
        })
        findings = self._run_assess(inst)
        non_ssl_findings = [f for f in findings
                            if f.name == "Unencrypted SAP HTTP Service Exposed"]
        self.assertEqual(len(non_ssl_findings), 1,
                         msg="Multiple HTTP ports should produce exactly one finding")

    @_patch_all_network
    def test_finding_lists_all_non_ssl_ports_in_detail(self, *mocks):
        inst = self._make_inst_with_ports({
            8000: "ICM HTTP",
            50000: "J2EE HTTP",
        })
        findings = self._run_assess(inst)
        non_ssl = next(f for f in findings
                       if f.name == "Unencrypted SAP HTTP Service Exposed")
        self.assertIn("8000", non_ssl.detail)
        self.assertIn("50000", non_ssl.detail)

    @_patch_all_network
    def test_ssl_confirmed_port_excluded(self, *mocks):
        """Port whose service was fingerprinted as SSL should not appear in finding."""
        inst = self._make_inst_with_ports({8000: "ICM HTTP"})
        # Fingerprinting marked this port as actually SSL
        inst.services["icm"] = {"port": 8000, "ssl": True}
        findings = self._run_assess(inst)
        names = [f.name for f in findings]
        self.assertNotIn("Unencrypted SAP HTTP Service Exposed", names)

    @_patch_all_network
    def test_finding_severity_is_high(self, *mocks):
        inst = self._make_inst_with_ports({8000: "ICM HTTP"})
        findings = self._run_assess(inst)
        non_ssl = next((f for f in findings
                        if f.name == "Unencrypted SAP HTTP Service Exposed"), None)
        self.assertIsNotNone(non_ssl)
        self.assertEqual(non_ssl.severity, Severity.HIGH)

    @_patch_all_network
    def test_only_https_ports_no_finding(self, *mocks):
        inst = self._make_inst_with_ports({
            4300: "ICM HTTPS",
            443: "HTTPS",
            8443: "HTTPS (alt)",
        })
        findings = self._run_assess(inst)
        names = [f.name for f in findings]
        self.assertNotIn("Unencrypted SAP HTTP Service Exposed", names)


# ═══════════════════════════════════════════════════════════════════════════
# 10. Multi-SID grouping logic
#     The grouping runs inside discover_systems. We test the logic directly
#     by replicating the exact grouping algorithm on Python objects.
# ═══════════════════════════════════════════════════════════════════════════

def _group_by_sid(sys_obj):
    """
    Replicate the multi-SID grouping from discover_systems so we can unit-test
    it independently.  Returns a list of SAPSystem objects (one per SID).
    """
    sid_groups = {}
    for inst in sys_obj.instances:
        inst_sid = inst.info.get("_discovered_sid", sys_obj.sid)
        if inst_sid not in sid_groups:
            sid_groups[inst_sid] = []
        sid_groups[inst_sid].append(inst)

    if len(sid_groups) <= 1:
        return [sys_obj]

    result = []
    for sid, inst_group in sid_groups.items():
        new_sys = SAPSystem(
            sid=sid,
            hostname=sys_obj.hostname,
            instances=inst_group,
            kernel=sys_obj.kernel,
            system_type=sys_obj.system_type,
        )
        result.append(new_sys)
    return result


class TestMultiSidGrouping(unittest.TestCase):
    def _inst(self, nr, sid=None):
        inst = SAPInstance(host="h", ip="10.10.1.5", instance_nr=nr)
        if sid:
            inst.info["_discovered_sid"] = sid
        return inst

    def test_single_sid_returns_one_system(self):
        sys_obj = SAPSystem(sid="AED")
        sys_obj.instances = [self._inst("00", "AED"), self._inst("01", "AED")]
        result = _group_by_sid(sys_obj)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].sid, "AED")

    def test_two_sids_returns_two_systems(self):
        sys_obj = SAPSystem(sid="AED")
        sys_obj.instances = [
            self._inst("00", "AED"),
            self._inst("01", "AED"),
            self._inst("02", "AEQ"),
            self._inst("03", "AEQ"),
        ]
        result = _group_by_sid(sys_obj)
        self.assertEqual(len(result), 2)
        sids = {s.sid for s in result}
        self.assertEqual(sids, {"AED", "AEQ"})

    def test_instances_correctly_distributed(self):
        sys_obj = SAPSystem(sid="AED")
        sys_obj.instances = [
            self._inst("00", "AED"),
            self._inst("01", "AED"),
            self._inst("02", "AEQ"),
            self._inst("03", "AEQ"),
        ]
        result = _group_by_sid(sys_obj)
        aed = next(s for s in result if s.sid == "AED")
        aeq = next(s for s in result if s.sid == "AEQ")
        self.assertEqual({i.instance_nr for i in aed.instances}, {"00", "01"})
        self.assertEqual({i.instance_nr for i in aeq.instances}, {"02", "03"})

    def test_no_discovered_sid_falls_back_to_system_sid(self):
        """Instances without _discovered_sid are grouped under the parent SID."""
        sys_obj = SAPSystem(sid="PRD")
        inst_no_tag = self._inst("00")   # no _discovered_sid
        inst_tagged = self._inst("01", "PRD")
        sys_obj.instances = [inst_no_tag, inst_tagged]
        result = _group_by_sid(sys_obj)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].sid, "PRD")

    def test_three_sids(self):
        sys_obj = SAPSystem(sid="A01")
        sys_obj.instances = [
            self._inst("00", "A01"),
            self._inst("02", "A02"),
            self._inst("04", "A03"),
        ]
        result = _group_by_sid(sys_obj)
        self.assertEqual(len(result), 3)

    def test_hostname_copied_to_split_systems(self):
        sys_obj = SAPSystem(sid="X", hostname="sapserver01")
        sys_obj.instances = [self._inst("00", "AA"), self._inst("01", "BB")]
        result = _group_by_sid(sys_obj)
        for s in result:
            self.assertEqual(s.hostname, "sapserver01")


# ═══════════════════════════════════════════════════════════════════════════
# 11. CVE-2025-31324 check (mocked HTTP)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckCve202531324(unittest.TestCase):
    def _mock_response(self, status_code, text=""):
        r = MagicMock()
        r.status_code = status_code
        r.text = text
        return r

    @patch("SAPology.requests.get")
    def test_200_with_failed_returns_finding(self, mock_get):
        mock_get.return_value = self._mock_response(200, "FAILED: no file uploaded")
        f = check_cve_2025_31324("10.0.0.1", 50000)
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.CRITICAL)

    @patch("SAPology.requests.get")
    def test_200_without_failed_returns_none(self, mock_get):
        """200 from a generic server (no FAILED) must not trigger finding."""
        mock_get.return_value = self._mock_response(200, "<html>Welcome</html>")
        f = check_cve_2025_31324("10.0.0.1", 50000)
        self.assertIsNone(f)

    @patch("SAPology.requests.get")
    def test_200_with_sapcontrol_body_returns_none(self, mock_get):
        """200 with SAPControl WSDL in body is a false positive — skip it."""
        body = "FAILED: something SAPControl GetProcessList wsdl here"
        mock_get.return_value = self._mock_response(200, body)
        f = check_cve_2025_31324("10.0.0.1", 50000)
        self.assertIsNone(f)

    @patch("SAPology.requests.get")
    def test_405_returns_finding(self, mock_get):
        """HTTP 405 (Method Not Allowed) confirms VC endpoint exists."""
        mock_get.return_value = self._mock_response(405, "Method Not Allowed")
        f = check_cve_2025_31324("10.0.0.1", 50000)
        self.assertIsNotNone(f)

    @patch("SAPology.requests.get")
    def test_405_with_sapcontrol_body_returns_none(self, mock_get):
        mock_get.return_value = self._mock_response(405, "sapcontrol wsdl")
        f = check_cve_2025_31324("10.0.0.1", 50000)
        self.assertIsNone(f)

    @patch("SAPology.requests.get")
    def test_401_returns_none(self, mock_get):
        mock_get.return_value = self._mock_response(401)
        self.assertIsNone(check_cve_2025_31324("10.0.0.1", 50000))

    @patch("SAPology.requests.get")
    def test_403_returns_none(self, mock_get):
        mock_get.return_value = self._mock_response(403)
        self.assertIsNone(check_cve_2025_31324("10.0.0.1", 50000))

    @patch("SAPology.requests.get")
    def test_404_returns_none(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        self.assertIsNone(check_cve_2025_31324("10.0.0.1", 50000))

    @patch("SAPology.requests.get")
    def test_finding_port_matches_argument(self, mock_get):
        mock_get.return_value = self._mock_response(200, "FAILED: no file")
        f = check_cve_2025_31324("10.0.0.1", 50200)
        self.assertEqual(f.port, 50200)

    @patch("SAPology.requests.get",
           side_effect=SAPology.requests.exceptions.ConnectionError("refused"))
    def test_connection_error_returns_none(self, mock_get):
        self.assertIsNone(check_cve_2025_31324("10.0.0.1", 50000))


# ═══════════════════════════════════════════════════════════════════════════
# 12. CVE-2022-41272 / P4 service check (mocked socket)
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckCve202241272(unittest.TestCase):
    def _make_socket(self, recv_data=b""):
        sock = MagicMock()
        sock.recv.return_value = recv_data
        return sock

    @patch("SAPology.socket.socket")
    def test_v1_response_returns_finding(self, mock_socket_cls):
        sock = self._make_socket(b"v1\x00\x00some P4 data")
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50004)
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.CRITICAL)

    @patch("SAPology.socket.socket")
    def test_non_v1_response_returns_none(self, mock_socket_cls):
        sock = self._make_socket(b"HTTP/1.1 400 Bad Request")
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50004)
        self.assertIsNone(f)

    @patch("SAPology.socket.socket")
    def test_empty_response_returns_none(self, mock_socket_cls):
        sock = self._make_socket(b"")
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50004)
        self.assertIsNone(f)

    @patch("SAPology.socket.socket")
    def test_connection_error_returns_none(self, mock_socket_cls):
        sock = MagicMock()
        sock.connect.side_effect = socket.error("refused")
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50004)
        self.assertIsNone(f)

    @patch("SAPology.socket.socket")
    def test_finding_port_is_correct(self, mock_socket_cls):
        sock = self._make_socket(b"v1\x00some data")
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50104)
        self.assertEqual(f.port, 50104)

    @patch("SAPology.socket.socket")
    def test_internal_ip_extracted_into_detail(self, mock_socket_cls):
        # Craft a response where a dotted-decimal IP follows "v1"
        payload = b"v1\x18#p#4None:10.10.1.5:33170"
        sock = self._make_socket(payload)
        mock_socket_cls.return_value = sock
        f = check_cve_2022_41272("10.0.0.1", 50004)
        self.assertIsNotNone(f)
        self.assertIn("10.10.1.5", f.detail)


# ═══════════════════════════════════════════════════════════════════════════
# 13. SAP_PORTS constant integrity
# ═══════════════════════════════════════════════════════════════════════════

class TestSapPortsConstants(unittest.TestCase):
    def test_sap_ports_has_expected_services(self):
        for svc in ("dispatcher", "gateway", "ms_http", "icm_http",
                    "icm_https", "sapcontrol", "j2ee_http", "ms_internal"):
            self.assertIn(svc, SAP_PORTS, msg="SAP_PORTS missing key: %s" % svc)

    def test_sap_ports_values_are_tuples(self):
        for key, val in SAP_PORTS.items():
            self.assertIsInstance(val, tuple, msg="SAP_PORTS[%s] is not a tuple" % key)
            self.assertEqual(len(val), 2)

    def test_dispatcher_base_port(self):
        self.assertEqual(SAP_PORTS["dispatcher"][0], 3200)

    def test_gateway_base_port(self):
        self.assertEqual(SAP_PORTS["gateway"][0], 3300)

    def test_fixed_ports_has_443(self):
        self.assertIn(443, SAP_FIXED_PORTS)

    def test_rdp_in_non_sap_ports(self):
        self.assertIn(3389, NON_SAP_PORTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
