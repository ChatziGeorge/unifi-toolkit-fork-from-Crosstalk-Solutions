"""
Tests for the DNS audit (tools/house_arrest/dns_audit.py).

Policy, group and network shapes are copied from a live console
(2026-10-14): hand-built zone-wide DNS blocks using port-group objects,
UniFi's predefined rules at 30000+ and the pair default at 2147483647.
"""
import pytest

from tools.house_arrest import dns_audit as A
from tools.house_arrest import policies as P


pytestmark = pytest.mark.unit

INTERNAL = "zone-internal"
EXTERNAL = "zone-external"
GATEWAY = "zone-gateway"
WORK = "zone-work"

ZONES = [
    {"_id": INTERNAL, "name": "Internal", "zone_key": "internal", "network_ids": ["iot", "lan"]},
    {"_id": EXTERNAL, "name": "External", "zone_key": "external", "network_ids": []},
    {"_id": GATEWAY, "name": "Gateway", "zone_key": "gateway", "network_ids": []},
    {"_id": WORK, "name": "Work", "network_ids": ["work"]},
]

GROUPS = [
    {"_id": "pg-dns", "group_type": "port-group", "name": "DNS Port", "group_members": ["53"]},
    {"_id": "pg-dot", "group_type": "port-group", "name": "DoT Port", "group_members": ["853"]},
    {"_id": "pg-web", "group_type": "port-group", "name": "web", "group_members": ["80", "443"]},
    {"_id": "ag-rfc", "group_type": "address-group", "name": "RFC1918",
     "group_members": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
]


def net(nid, name, subnet, zone, ipv6=False, **kw):
    n = {"_id": nid, "name": name, "purpose": "corporate", "ip_subnet": subnet,
         "firewall_zone_id": zone, "dhcpd_dns_enabled": True,
         "dhcpd_dns_1": subnet.split("/")[0],
         "ipv6_interface_type": "pd" if ipv6 else "none",
         "internet_access_enabled": True}
    n.update(kw)
    return n


IOT = net("iot", "IoT", "10.20.3.1/27", INTERNAL, network_isolation_enabled=True)
LAN = net("lan", "LAN", "10.20.68.1/24", INTERNAL)
WORKNET = net("work", "Work", "10.20.16.1/26", WORK)
NETS = [IOT, LAN, WORKNET, {"_id": "wan", "name": "Internet 1", "purpose": "wan"}]


def pol(name, action, src_zone, dst_zone, index, *, predefined=False, src=None,
        dst=None, ip_version="BOTH", enabled=True, cst="ALL", states=None,
        protocol="all", schedule="ALWAYS", desc=""):
    s = {"matching_target": "ANY", "port_matching_type": "ANY", "zone_id": src_zone}
    s.update(src or {})
    d = {"matching_target": "ANY", "port_matching_type": "ANY", "zone_id": dst_zone}
    d.update(dst or {})
    return {"_id": name, "name": name, "action": action, "index": index,
            "predefined": predefined, "enabled": enabled, "ip_version": ip_version,
            "connection_state_type": cst, "connection_states": states or [],
            "protocol": protocol, "schedule": {"mode": schedule},
            "description": desc, "source": s, "destination": d}


DNS_OBJ = {"port_matching_type": "OBJECT", "port_group_id": "pg-dns"}
DOT_OBJ = {"port_matching_type": "OBJECT", "port_group_id": "pg-dot"}


def defaults():
    """UniFi's predefined rules for the pairs the audit reads."""
    return [
        pol("Block Invalid Traffic", "BLOCK", INTERNAL, EXTERNAL, 30000,
            predefined=True, cst="CUSTOM", states=["INVALID"]),
        pol("Allow All Traffic", "ALLOW", INTERNAL, EXTERNAL, 2147483647, predefined=True),
        pol("Allow All Traffic", "ALLOW", WORK, EXTERNAL, 2147483647, predefined=True),
        pol("Isolated Networks", "BLOCK", INTERNAL, INTERNAL, 30004, predefined=True,
            src={"matching_target": "IP", "matching_target_type": "SPECIFIC",
                 "ips": ["10.20.3.0/27"]}),
        pol("Allow All Traffic", "ALLOW", INTERNAL, INTERNAL, 2147483647, predefined=True),
        pol("Allow DNS", "ALLOW", INTERNAL, GATEWAY, 30000, predefined=True,
            dst={"port": "53", "port_matching_type": "SPECIFIC"}, protocol="tcp_udp"),
        pol("Allow All Traffic", "ALLOW", INTERNAL, GATEWAY, 2147483647, predefined=True),
    ]


def user_rules(ip_version="IPV4"):
    return [
        pol("[Internal] Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001,
            dst=DNS_OBJ, ip_version=ip_version),
        pol("[Internal] Block DoT", "BLOCK", INTERNAL, EXTERNAL, 10002,
            dst=DOT_OBJ, ip_version=ip_version),
    ]


def run(policies, nets=NETS, interception=None):
    return A.audit(nets, ZONES, policies, GROUPS, interception or {})


def row(result, name):
    return next(r for r in result["rows"] if r["name"] == name)


def cell(r, key):
    return next(c for c in r["channels"] if c["key"] == key)


class TestRecognisesHandBuiltRules:
    def test_zone_wide_port_group_block_counts(self):
        r = row(run(defaults() + user_rules()), "IoT")
        ch = cell(r, A.CH_DNS)
        assert (ch["state"], ch["value"]) == ("good", "Blocked")
        assert "[Internal] Block DNS" in ch["detail"]
        assert r["verdict"]["label"] == "Locked"

    def test_zone_without_rules_is_open(self):
        r = row(run(defaults() + user_rules()), "Work")
        assert cell(r, A.CH_DNS)["value"] == "Open"
        assert r["verdict"]["label"] == "Open"

    def test_disabled_rule_does_not_count(self):
        rules = user_rules()
        rules[0]["enabled"] = False
        assert cell(row(run(defaults() + rules), "IoT"), A.CH_DNS)["value"] == "Open"

    def test_earlier_full_allow_wins_over_block(self):
        allow = pol("Allow everything out", "ALLOW", INTERNAL, EXTERNAL, 10000)
        ch = cell(row(run(defaults() + [allow] + user_rules()), "IoT"), A.CH_DNS)
        assert ch["value"] == "Open"
        assert "Allow everything out" in ch["detail"]

    def test_port_group_without_53_does_not_block_dns(self):
        web = pol("Block web", "BLOCK", INTERNAL, EXTERNAL, 10000,
                  dst={"port_matching_type": "OBJECT", "port_group_id": "pg-web"})
        assert cell(row(run(defaults() + [web]), "IoT"), A.CH_DNS)["value"] == "Open"

    def test_unknown_port_group_is_never_full(self):
        rule = pol("Mystery", "BLOCK", INTERNAL, EXTERNAL, 10000,
                   dst={"port_matching_type": "OBJECT", "port_group_id": "missing"})
        assert cell(row(run(defaults() + [rule]), "IoT"), A.CH_DNS)["state"] != "good"


class TestIpv6:
    def test_ipv4_only_rule_is_complete_when_ipv6_is_off(self):
        ch = cell(row(run(defaults() + user_rules("IPV4")), "IoT"), A.CH_DNS)
        assert ch["value"] == "Blocked" and ch["v6"] == "n/a"
        assert "IPv6 is off" in ch["detail"]

    def test_ipv4_only_rule_warns_when_ipv6_is_on(self):
        nets = [dict(IOT, ipv6_interface_type="pd"), LAN, WORKNET]
        ch = cell(row(run(defaults() + user_rules("IPV4"), nets), "IoT"), A.CH_DNS)
        assert (ch["state"], ch["value"]) == ("warn", "IPv4 only")

    def test_missing_ipv6_field_is_treated_as_on(self):
        n = dict(IOT)
        n.pop("ipv6_interface_type")
        assert A.network_has_ipv6(n) is True

    def test_ipv6_off_open_network_is_open_not_ipv6_only(self):
        ch = cell(row(run(defaults()), "IoT"), A.CH_DNS)
        assert ch["value"] == "Open"


class TestPredefinedRules:
    def test_return_and_invalid_rules_never_decide(self):
        ret = pol("Allow X (Return)", "ALLOW", INTERNAL, EXTERNAL, 9000,
                  predefined=True, cst="RESPOND_ONLY", states=["RELATED", "ESTABLISHED"])
        ch = cell(row(run(defaults() + [ret] + user_rules()), "IoT"), A.CH_DNS)
        assert ch["value"] == "Blocked"

    def test_isolation_blocks_dns_to_other_networks(self):
        ch = cell(row(run(defaults()), "IoT"), A.CH_LAN)
        assert ch["value"] == "Blocked"
        assert "Isolated Networks" in ch["detail"]

    def test_not_isolated_network_reaches_other_networks(self):
        assert cell(row(run(defaults()), "LAN"), A.CH_LAN)["value"] == "Open"

    def test_internet_toggle_rule_blocks(self):
        toggle = pol("Block 10.20.68.0/24 Internet Access", "BLOCK", INTERNAL, EXTERNAL,
                     30001, predefined=True,
                     src={"matching_target": "IP", "matching_target_type": "SPECIFIC",
                          "ips": ["10.20.68.0/24"]})
        ch = cell(row(run(defaults() + [toggle]), "LAN"), A.CH_DNS)
        assert ch["value"] == "Blocked" and "built-in" in ch["detail"]

    def test_only_network_in_zone_has_no_lan_path(self):
        assert cell(row(run(defaults()), "Work"), A.CH_LAN)["value"] == "n/a"


class TestSourcesAndNoise:
    def test_address_group_source_covering_subnet_is_full(self):
        rule = pol("RFC block", "BLOCK", INTERNAL, EXTERNAL, 10000, dst=DNS_OBJ,
                   src={"matching_target": "IP", "matching_target_type": "OBJECT",
                        "ip_group_id": "ag-rfc"})
        assert cell(row(run(defaults() + [rule]), "IoT"), A.CH_DNS)["value"] == "Blocked"

    def test_device_specific_block_is_partial(self):
        rule = pol("Kid's tablet", "BLOCK", INTERNAL, EXTERNAL, 10000, dst=DNS_OBJ,
                   src={"matching_target": "CLIENT", "client_macs": ["aa:bb:cc:dd:ee:ff"]})
        ch = cell(row(run(defaults() + [rule]), "IoT"), A.CH_DNS)
        assert (ch["state"], ch["value"]) == ("warn", "Partial")

    def test_scheduled_block_is_partial(self):
        rule = pol("Night", "BLOCK", INTERNAL, EXTERNAL, 10000, dst=DNS_OBJ,
                   schedule="EVERY_DAY")
        assert cell(row(run(defaults() + [rule]), "IoT"), A.CH_DNS)["value"] == "Partial"

    def test_app_and_domain_rules_are_ignored_for_port_paths(self):
        ads = pol("[Block] Ads Domains", "BLOCK", INTERNAL, EXTERNAL, 30001, predefined=True,
                  dst={"matching_target": "WEB", "web_domains": ["ads.example"]})
        ch = cell(row(run(defaults() + [ads]), "IoT"), A.CH_DNS)
        assert ch["value"] == "Open" and "Ads Domains" not in ch["detail"]

    def test_all_port_block_to_some_addresses_is_not_dns_protection(self):
        prov = pol("Block provider net", "BLOCK", INTERNAL, EXTERNAL, 10000,
                   dst={"matching_target": "IP", "ips": ["10.99.0.0/29"]})
        assert cell(row(run(defaults() + [prov]), "IoT"), A.CH_DNS)["value"] == "Open"

    def test_app_rule_makes_doh_neutral_not_green(self):
        app = pol("Block DoH", "BLOCK", INTERNAL, EXTERNAL, 10003,
                  dst={"matching_target": "APP", "app_ids": [1]})
        ch = cell(row(run(defaults() + [app]), "IoT"), A.CH_DOH)
        assert ch["state"] == "neutral" and ch["value"] == "Check in UniFi"


class TestResolverProblems:
    def test_blocked_public_dhcp_resolver_is_flagged(self):
        nets = [dict(IOT, dhcpd_dns_1="1.1.1.1"), LAN, WORKNET]
        r = row(run(defaults() + user_rules(), nets), "IoT")
        assert r["verdict"]["label"] == "DNS broken?"
        assert "1.1.1.1" in r["problems"][0]

    def test_gateway_resolver_is_fine(self):
        assert row(run(defaults() + user_rules()), "IoT")["problems"] == []


class TestSuggestions:
    def test_only_gaps_get_suggestions(self):
        sug = run(defaults() + user_rules())["suggestions"]
        zones = {s["zone_name"] for s in sug if s["channel"] in (A.CH_DNS, A.CH_DOT)}
        assert zones == {"Work"}

    def test_both_styles_offered_with_matching_sources(self):
        sug = [s for s in run(defaults())["suggestions"]
               if s["zone_name"] == "Work" and s["channel"] == A.CH_DNS]
        by_style = {s["style"]: s for s in sug}
        assert set(by_style) == {A.STYLE_NETWORK, A.STYLE_ZONE}
        net_src = by_style[A.STYLE_NETWORK]["policies"][-1]["source"]
        zone_src = by_style[A.STYLE_ZONE]["policies"][-1]["source"]
        assert net_src["matching_target"] == "NETWORK" and net_src["network_ids"] == ["work"]
        assert zone_src["matching_target"] == "ANY" and zone_src["zone_id"] == WORK

    def test_rules_are_written_for_both_families_when_ipv6_is_off(self):
        s = next(s for s in run(defaults())["suggestions"] if s["zone_name"] == "Work")
        assert s["family"] == "both"
        assert all(p["ip_version"] == "BOTH" for p in s["policies"])

    def test_every_suggested_rule_is_releasable(self):
        for s in run(defaults())["suggestions"]:
            for p in s["policies"]:
                assert P.is_dns_policy(dict(p, predefined=False))

    def test_public_dhcp_resolver_gets_an_allow_first(self):
        nets = [IOT, LAN, dict(WORKNET, dhcpd_dns_1="9.9.9.9")]
        s = next(s for s in run(defaults(), nets)["suggestions"]
                 if s["zone_name"] == "Work" and s["channel"] == A.CH_DNS)
        assert [p["action"] for p in s["policies"]] == ["ALLOW", "BLOCK"]
        assert s["policies"][0]["destination"]["ips"] == ["9.9.9.9"]

    def test_ipv6_gap_suggests_ipv6_rule_and_names_the_alternative(self):
        nets = [dict(IOT, ipv6_interface_type="pd"), LAN, WORKNET]
        s = next(s for s in run(defaults() + user_rules("IPV4"), nets)["suggestions"]
                 if s["zone_name"] == "Internal" and s["channel"] == A.CH_DNS)
        assert s["family"] == "v6"
        assert s["policies"][-1]["ip_version"] == "IPV6"
        assert "IP Version to Both" in s["improves"][0]

    def test_no_internet_network_gets_no_internet_suggestion(self):
        nets = [IOT, LAN, dict(WORKNET, internet_access_enabled=False)]
        sug = run(defaults(), nets)["suggestions"]
        assert not [s for s in sug if s["zone_name"] == "Work"]


class TestReach:
    """reach.py: network-to-network reachability from the ordered rules."""

    HOT = "zone-hotspot"
    GUESTS = net("guests", "Guests", "10.20.200.1/27", "zone-hotspot")

    def zones(self):
        return ZONES + [{"_id": self.HOT, "name": "Hotspot", "zone_key": "hotspot",
                         "network_ids": ["guests"]}]

    def hotspot_rules(self):
        return [
            pol("Allow All Traffic", "ALLOW", INTERNAL, self.HOT, 2147483647, predefined=True),
            pol("Allow Public DNS", "ALLOW", self.HOT, INTERNAL, 30000, predefined=True,
                dst={"port": "53", "port_matching_type": "SPECIFIC"}),
            pol("Post-Authorization Restrictions", "BLOCK", self.HOT, INTERNAL, 30001,
                predefined=True, ip_version="IPV4"),
            pol("Allow Return Traffic", "ALLOW", self.HOT, INTERNAL, 30002,
                predefined=True, cst="RESPOND_ONLY", states=["RELATED", "ESTABLISHED"]),
            pol("Block All Traffic", "BLOCK", self.HOT, INTERNAL, 2147483647, predefined=True),
        ]

    def test_replies_blocked_means_no_reach(self):
        from tools.house_arrest import reach as R
        r = R.reach(LAN, self.GUESTS, self.zones(), defaults() + self.hotspot_rules(), {})
        assert r["state"] == R.BLOCKED and r["via"] == "replies"
        assert r["by"]["name"] == "Post-Authorization Restrictions"

    def test_hover_names_the_rule_that_keeps_networks_apart(self):
        from tools.house_arrest import reach as R
        intervlan = pol("Block Inter-VLAN", "BLOCK", INTERNAL, INTERNAL, 10006,
                        src={"matching_target": "IP", "ips": ["10.0.0.0/8"]},
                        dst={"matching_target": "IP", "ips": ["10.0.0.0/8"]})
        s = R.isolation_summary(LAN, [IOT, LAN], ZONES, defaults() + [intervlan], [])
        text = R.isolation_cell(s, flag_on=False)["text"]
        assert 'Kept apart by: your rule "Block Inter-VLAN" (IoT (both ways))' in text

    def test_guest_network_is_isolated_by_zone_with_builtin_asterisk(self):
        from tools.house_arrest import reach as R
        # Nothing reaches guests: LAN's new traffic blocked by a user rule.
        block_in = pol("No LAN to guests", "BLOCK", INTERNAL, self.HOT, 10000)
        s = R.isolation_summary(self.GUESTS, [IOT, LAN, self.GUESTS], self.zones(),
                                defaults() + self.hotspot_rules() + [block_in], [])
        cell = R.isolation_cell(s, flag_on=False)
        assert (cell["state"], cell["label"]) == ("good", "Isolated by zone *")
        assert "Can reach this network:" not in cell["text"]
        assert "made by UniFi itself" in cell["text"] and "port 53" in cell["text"]

    def test_user_allow_into_isolated_network_is_partial(self):
        from tools.house_arrest import reach as R
        allow = pol("LAN to guests", "ALLOW", INTERNAL, self.HOT, 10000,
                    src={"matching_target": "NETWORK", "network_ids": ["lan"]})
        block_rest = pol("Nothing else to guests", "BLOCK", INTERNAL, self.HOT, 10001)
        back = pol("LAN to guests (Return)", "ALLOW", self.HOT, INTERNAL, 29999,
                   predefined=True, cst="RESPOND_ONLY", states=["ESTABLISHED"],
                   dst={"matching_target": "NETWORK", "network_ids": ["lan"]})
        s = R.isolation_summary(self.GUESTS, [IOT, LAN, self.GUESTS], self.zones(),
                                defaults() + self.hotspot_rules() + [allow, block_rest, back], [])
        cell = R.isolation_cell(s, flag_on=False)
        assert (cell["state"], cell["label"]) == ("warn", "Partial")
        assert "LAN (everything, through your rule \"LAN to guests\")" in cell["text"]

    def test_default_open_is_off_and_grey(self):
        from tools.house_arrest import reach as R
        # Neither network isolated: drop UniFi's "Isolated Networks" rule.
        rules = [p for p in defaults() if p["name"] != "Isolated Networks"]
        s = R.isolation_summary(LAN, [IOT, LAN], ZONES, rules, [])
        cell = R.isolation_cell(s, flag_on=False)
        assert (cell["state"], cell["label"]) == ("neutral", "Off")

    def test_network_target_destination_is_exact(self):
        assert A.dest_coverage_subnets({"matching_target": "NETWORK", "network_ids": ["x"]},
                                       [None], {}, ["y"]) == A.NONE


class TestWifiIsolationCell:
    def test_states_and_colours(self):
        on = {"name": "A", "enabled": True, "isolated": True}
        off = {"name": "B", "enabled": True, "isolated": False}
        dis = {"name": "C", "enabled": False, "isolated": True}
        assert P.wifi_isolation_cell([on], "N")["state"] == "good"
        assert P.wifi_isolation_cell([off], "N")["state"] == "neutral"   # a choice, not a fault
        assert P.wifi_isolation_cell([on, off], "N")["label"] == "Mixed"
        cell = P.wifi_isolation_cell([dis], "N")
        assert cell["label"] == "Disabled · On" and "C (on)" in cell["detail"]
        assert P.wifi_isolation_cell([], "N")["label"] == "No Wi-Fi"

    def test_per_password_networks_count(self):
        w = {"networkconf_id": "lan", "private_preshared_keys_enabled": True,
             "private_preshared_keys": [{"networkconf_id": "iot"}, {"networkconf_id": "lan"}]}
        assert P.wlan_networks(w) == ["lan", "iot"]
        assert P.wlan_networks(dict(w, private_preshared_keys_enabled=False)) == ["lan"]


class TestInternetColours:
    def test_allowed_green_blocked_red(self):
        rows = P.build_isolation_matrix(
            [dict(IOT), dict(LAN, internet_access_enabled=False)], [])["rows"]
        by = {r["name"]: r["cells"]["internet"]["state"] for r in rows}
        assert by == {"IoT": "good", "LAN": "bad"}




class TestRuleCheck:
    """rule_check.py: per-rule findings, any console."""

    def run(self, rules, nets=None, groups=GROUPS):
        from tools.house_arrest import rule_check as RC
        return RC.check(rules, ZONES, nets or [IOT, LAN, WORKNET], groups)

    def row(self, res, name):
        return next(r for r in res["rows"] if r["name"] == name)

    def test_shadowed_rule_never_takes_effect(self):
        allow = pol("Allow all out", "ALLOW", INTERNAL, EXTERNAL, 10000)
        block = pol("Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001, dst=DNS_OBJ)
        r = self.row(self.run([allow, block]), "Block DNS")
        assert r["status"] == "issue" and "Never takes effect" in r["findings"][0]["text"]

    def test_duplicate_is_flagged(self):
        a = pol("Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001, dst=DNS_OBJ)
        b = pol("Block DNS again", "BLOCK", INTERNAL, EXTERNAL, 10002, dst=DNS_OBJ)
        r = self.row(self.run([a, b]), "Block DNS again")
        assert any("Duplicate" in f["text"] for f in r["findings"])

    def test_narrower_earlier_rule_does_not_shadow(self):
        narrow = pol("Kid tablet", "ALLOW", INTERNAL, EXTERNAL, 10000,
                     src={"matching_target": "CLIENT", "client_macs": ["aa:bb:cc:dd:ee:ff"]})
        block = pol("Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001, dst=DNS_OBJ)
        r = self.row(self.run([narrow, block]), "Block DNS")
        assert not any("Never takes effect" in f["text"] for f in r["findings"])

    def test_empty_group_matches_nothing(self):
        groups = GROUPS + [{"_id": "ag-empty", "group_type": "address-group",
                            "name": "Empty", "group_members": []}]
        rule = pol("Block empty", "BLOCK", INTERNAL, EXTERNAL, 10000,
                   dst={"matching_target": "IP", "matching_target_type": "OBJECT",
                        "ip_group_id": "ag-empty"})
        r = self.row(self.run([rule], groups=groups), "Block empty")
        assert r["status"] == "issue" and "empty" in r["findings"][0]["text"]

    def test_ipv4_only_block_is_issue_when_ipv6_is_on(self):
        rule = pol("Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001, dst=DNS_OBJ, ip_version="IPV4")
        on = self.row(self.run([rule], [dict(IOT, ipv6_interface_type="pd"), LAN]), "Block DNS")
        off = self.row(self.run([rule]), "Block DNS")
        assert on["status"] == "issue" and off["status"] == "improve"

    def test_missing_sibling_block_is_noted(self):
        rules = [pol("[Internal] Block DoT", "BLOCK", INTERNAL, EXTERNAL, 10002, dst=DOT_OBJ),
                 pol("[Work] Block Countries", "BLOCK", WORK, EXTERNAL, 10000,
                     dst={"matching_target": "REGION"})]
        work_dot_missing = self.run(rules)
        # Only one zone has "block dot", so nothing to compare yet.
        assert not any("Similar rules" in f["text"] for r in work_dot_missing["rows"] for f in r["findings"])

    def test_unused_group_listed(self):
        res = self.run([pol("Block DNS", "BLOCK", INTERNAL, EXTERNAL, 10001, dst=DNS_OBJ)])
        names = {g["name"] for g in res["unused_groups"]}
        assert "DoT Port" in names and "DNS Port" not in names
