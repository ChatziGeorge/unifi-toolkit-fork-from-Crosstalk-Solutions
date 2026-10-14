"""
DNS audit: what actually decides each network's DNS traffic, and what is
missing.

The DNS Lockdown form only ever knew about rules House Arrest wrote itself.
A console where the owner had already built DNS blocks by hand (zone-wide,
with port-group and address-group objects) showed every network as unlocked,
and offered to stack a second set of rules on top. This module reads EVERY
policy instead - custom and predefined, in evaluation order - and reports,
per network and per DNS path, which rule decides the traffic.

MEASURED 2026-10-14 (Network 9.x, one console):
  * Predefined policies share the ordered list with custom ones: custom rules
    sit at 10000+, UniFi's own at 30000+ ("Isolated Networks", "Block Invalid
    Traffic", "Block <subnet> Internet Access" from a network's internet
    toggle), and the pair's default ("Allow All Traffic" / "Block All
    Traffic") at 2147483647. Walking all of them in index order therefore
    models isolation, the internet toggle and the default with no special
    cases.
  * "(Return)" policies are RESPOND_ONLY and "Block Invalid Traffic" is
    CUSTOM [INVALID]: neither matches a NEW DNS query, so both are skipped.
  * Port and address objects: `port_matching_type: OBJECT` + `port_group_id`,
    `matching_target_type: OBJECT` + `ip_group_id`. Both ids resolve through
    legacy `rest/firewallgroup` (`group_type` port-group / address-group,
    `group_members` as strings, ports may be ranges "a-b").
  * App-based destinations (`matching_target: APP`, `app_ids`) cannot be named
    from any endpoint found so far, so an app rule is reported as an app rule,
    never as "DoH is blocked".

The walk answers one question per (network, path, IP family): for a NEW
connection from this network to that kind of destination, which rule decides
it first? A rule that only covers part of the traffic (some devices, some
servers, a schedule) does not decide; it is recorded and the walk continues.
"""
import ipaddress
from typing import Dict, Iterable, List, Optional, Tuple

from tools.house_arrest import policies as P


# Channel keys, in the order the UI shows them.
CH_DNS = "dns_internet"
CH_DOT = "dot_internet"
CH_DOH = "doh"
CH_LAN = "dns_lan"

CHANNEL_LABELS = {
    CH_DNS: "DNS to the internet",
    CH_DOT: "DNS-over-TLS",
    CH_DOH: "DNS-over-HTTPS",
    CH_LAN: "DNS to other networks",
}

# Cell / verdict states (match the matrix vocabulary in the UI).
GOOD, WARN, BAD, NEUTRAL = "good", "warn", "bad", "neutral"

FULL, PARTIAL, NONE = "full", "partial", "none"

# Destinations matched by application / domain / country rather than address.
NON_PORT_TARGETS = ("APP", "APP_CATEGORY", "WEB", "DOMAIN", "REGION")


def network_has_ipv6(network: Dict) -> bool:
    """
    Does this network hand its devices IPv6 at all?

    MEASURED 2026-10-14: every LAN document carries `ipv6_interface_type`,
    "none" when IPv6 is off for that network, even while the WAN has a
    delegated prefix. With it off, devices have no routable IPv6, so an
    IPv4-only block is complete. A missing field (older firmware) is treated
    as IPv6 on: unknown must not read as safe.
    """
    return (network.get("ipv6_interface_type") or "unknown").lower() != "none"

FAMILIES = ("v4", "v6")

STYLE_NETWORK = "network"
STYLE_ZONE = "zone"

STYLES = {
    STYLE_NETWORK: {
        "label": "One rule set per network",
        "pros": [
            "Precise: only the networks you tick are affected.",
            "Each network can be released on its own.",
            "Networks you add later stay untouched until you decide.",
        ],
        "cons": [
            "More rules in the Policy Table.",
            "A new network in the zone is NOT covered until you add it.",
        ],
    },
    STYLE_ZONE: {
        "label": "One rule set per zone",
        "pros": [
            "Fewest rules: one set covers every network in the zone.",
            "Networks you add to the zone later are covered automatically.",
            "Same shape as rules built by hand in the UniFi UI.",
        ],
        "cons": [
            "All-or-nothing: every network in the zone gets the same rules.",
            "Exempting one network later needs an extra allow rule.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Object resolution
# ---------------------------------------------------------------------------

def group_index(groups: Optional[List[Dict]]) -> Dict[str, List[str]]:
    """{group _id: members} from legacy rest/firewallgroup."""
    out: Dict[str, List[str]] = {}
    for g in groups or []:
        gid = g.get("_id")
        if gid:
            out[gid] = [str(m).strip() for m in (g.get("group_members") or []) if str(m).strip()]
    return out


def group_names(groups: Optional[List[Dict]]) -> Dict[str, str]:
    return {g.get("_id"): g.get("name") or "group" for g in groups or [] if g.get("_id")}


def _port_spec(side: Dict, groups: Dict[str, List[str]]) -> Optional[Tuple[bool, List[str]]]:
    """
    (negated, members) for a side's ports, ([], False) meaning ANY.
    None when the ports cannot be determined (unknown group / type).
    """
    pmt = (side.get("port_matching_type") or "ANY").upper()
    neg = bool(side.get("match_opposite_ports"))
    if pmt == "ANY":
        return (False, [])
    if pmt == "SPECIFIC":
        raw = str(side.get("port") or "")
        members = [p.strip() for p in raw.split(",") if p.strip()]
        return (neg, members) if members else None
    if pmt == "OBJECT":
        members = groups.get(side.get("port_group_id") or "")
        return (neg, members) if members else None
    return None


def _port_hits(members: List[str], port: int) -> bool:
    for m in members:
        if "-" in m:
            lo, _, hi = m.partition("-")
            if lo.strip().isdigit() and hi.strip().isdigit() and int(lo) <= port <= int(hi):
                return True
        elif m.isdigit() and int(m) == port:
            return True
    return False


def port_coverage(side: Dict, port: int, groups: Dict[str, List[str]]) -> str:
    spec = _port_spec(side, groups)
    if spec is None:
        return PARTIAL                      # unknown: never claim full, never ignore
    neg, members = spec
    if not members:
        return FULL                         # ANY
    hit = _port_hits(members, port)
    return FULL if hit != neg else NONE


def _ip_members(side: Dict, groups: Dict[str, List[str]]) -> Optional[List[str]]:
    """IP/CIDR/range strings for an IP-target side, None if unresolvable."""
    if (side.get("matching_target_type") or "").upper() == "OBJECT" or side.get("ip_group_id"):
        members = groups.get(side.get("ip_group_id") or "")
        if members is not None:
            return members
    ips = side.get("ips")
    if ips:
        return [str(i).strip() for i in ips if str(i).strip()]
    return None


def _as_networks(members: Iterable[str]) -> List:
    """Parse IPs / CIDRs / 'a-b' ranges into ip_network objects (best effort)."""
    out = []
    for m in members:
        try:
            if "-" in m and "/" not in m:
                lo, _, hi = m.partition("-")
                out.extend(ipaddress.summarize_address_range(
                    ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())))
            else:
                out.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            continue
    return out


def _subnet(network: Dict):
    try:
        return ipaddress.ip_network(network.get("ip_subnet") or "", strict=False)
    except ValueError:
        return None


def _cover_subnet(nets: List, subnet) -> str:
    if subnet is None:
        return PARTIAL
    if any(subnet.version == n.version and subnet.subnet_of(n) for n in nets):
        return FULL
    if any(subnet.version == n.version and subnet.overlaps(n) for n in nets):
        return PARTIAL
    return NONE


def _negate(cov: str) -> str:
    return {FULL: NONE, NONE: FULL}.get(cov, PARTIAL)


def source_coverage(src: Dict, network: Dict, groups: Dict[str, List[str]]) -> str:
    """Does this policy source match ALL / SOME / NONE of the network's devices?"""
    mt = (src.get("matching_target") or "ANY").upper()
    if mt == "ANY":
        return FULL
    if mt == "NETWORK":
        ids = src.get("network_ids") or []
        hit = network.get("_id") in ids
        return FULL if hit != bool(src.get("match_opposite_networks")) else NONE
    if mt == "IP":
        members = _ip_members(src, groups)
        if members is None:
            return PARTIAL
        cov = _cover_subnet(_as_networks(members), _subnet(network))
        return _negate(cov) if src.get("match_opposite_ips") else cov
    # CLIENT / MAC / device groups: specific devices only.
    return PARTIAL


def dest_coverage_any(dst: Dict, groups: Dict[str, List[str]]) -> Tuple[str, Optional[List[str]]]:
    """
    Destination coverage for "any server in that zone".

    Returns (coverage, exceptions): a negated IP list covers everything EXCEPT
    those addresses, which matter (they are usually the approved resolvers).
    """
    mt = (dst.get("matching_target") or "ANY").upper()
    if mt == "ANY":
        return FULL, None
    if mt == "IP":
        members = _ip_members(dst, groups)
        if members is not None and dst.get("match_opposite_ips"):
            return FULL, members
        return PARTIAL, None
    return PARTIAL, None                    # REGION, APP, WEB, NETWORK, ...


def dest_coverage_ip(dst: Dict, ip: str, groups: Dict[str, List[str]]) -> str:
    """Destination coverage for one specific server address."""
    mt = (dst.get("matching_target") or "ANY").upper()
    if mt == "ANY":
        return FULL
    if mt == "IP":
        members = _ip_members(dst, groups)
        if members is None:
            return PARTIAL
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return PARTIAL
        hit = any(addr.version == n.version and addr in n for n in _as_networks(members))
        return FULL if hit != bool(dst.get("match_opposite_ips")) else NONE
    return PARTIAL


def dest_coverage_subnets(dst: Dict, subnets: List, groups: Dict[str, List[str]],
                          network_ids: Optional[List[str]] = None) -> str:
    """
    Destination coverage for a set of LAN subnets (other networks in the zone).

    `network_ids` (same order as `subnets`, when known) lets a NETWORK-target
    destination be answered exactly instead of as "partial".
    """
    mt = (dst.get("matching_target") or "ANY").upper()
    if mt == "ANY":
        return FULL
    if mt == "IP":
        members = _ip_members(dst, groups)
        if members is None:
            return PARTIAL
        nets = _as_networks(members)
        covs = [_cover_subnet(nets, s) for s in subnets]
        if dst.get("match_opposite_ips"):
            covs = [_negate(c) for c in covs]
        if covs and all(c == FULL for c in covs):
            return FULL
        if any(c != NONE for c in covs):
            return PARTIAL
        return NONE
    if mt == "NETWORK" and network_ids:
        ids = dst.get("network_ids") or []
        neg = bool(dst.get("match_opposite_networks"))
        covs = [FULL if ((nid in ids) != neg) else NONE for nid in network_ids]
        if all(c == FULL for c in covs):
            return FULL
        return PARTIAL if any(c == FULL for c in covs) else NONE
    return PARTIAL


def protocol_coverage(policy: Dict, tcp: bool, udp: bool) -> str:
    """Does the policy's protocol match the transport(s) this path uses?"""
    proto = (policy.get("protocol") or "all").lower()
    if policy.get("match_opposite_protocol"):
        return PARTIAL
    if proto in ("all", "tcp_udp"):
        return FULL
    if proto == "tcp":
        return FULL if not udp else (PARTIAL if tcp else NONE)
    if proto == "udp":
        return FULL if not tcp else (PARTIAL if udp else NONE)
    return NONE


def family_applies(policy: Dict, family: str) -> bool:
    v = (policy.get("ip_version") or "BOTH").upper()
    return v == "BOTH" or (v == "IPV4" and family == "v4") or (v == "IPV6" and family == "v6")


def matches_new_connections(policy: Dict) -> bool:
    """RESPOND_ONLY (Return) and CUSTOM-without-NEW (Block Invalid) never match a new query."""
    cst = (policy.get("connection_state_type") or "ALL").upper()
    if cst == "ALL":
        return True
    if cst == "RESPOND_ONLY":
        return False
    return "NEW" in [str(s).upper() for s in policy.get("connection_states") or []]


def _combine(*covs: str) -> str:
    if NONE in covs:
        return NONE
    if PARTIAL in covs:
        return PARTIAL
    return FULL


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

def _rule_ref(p: Dict) -> Dict:
    return {
        "id": p.get("_id"),
        "name": p.get("name") or "(unnamed rule)",
        "action": p.get("action"),
        "index": p.get("index"),
        "ours": P.is_house_arrest(p),
        "predefined": bool(p.get("predefined")),
        "ip_version": (p.get("ip_version") or "BOTH").upper(),
    }


def pair_policies(policies: List[Dict], src_zone: str, dst_zone: str) -> List[Dict]:
    """Enabled policies in one zone pair, in evaluation order (lower index first)."""
    out = [p for p in policies or []
           if p.get("enabled") is not False
           and (p.get("source") or {}).get("zone_id") == src_zone
           and (p.get("destination") or {}).get("zone_id") == dst_zone]
    return sorted(out, key=lambda p: (p.get("index") if isinstance(p.get("index"), int) else 0))


def walk(
    ordered: List[Dict],
    network: Dict,
    family: str,
    port: int,
    tcp: bool,
    udp: bool,
    groups: Dict[str, List[str]],
    dest_fn,
) -> Dict:
    """
    First rule that fully decides NEW traffic from `network` on `port`.

    dest_fn(destination) -> coverage (or (coverage, exceptions)).

    Returns {"decided": "BLOCK"|"ALLOW"|None, "rule": ref|None,
             "partial": [refs of rules matching only part, evaluated BEFORE
                         the deciding rule], "except": [ips] }
    """
    partial: List[Dict] = []
    for p in ordered:
        if not family_applies(p, family) or not matches_new_connections(p):
            continue
        action = (p.get("action") or "").upper()
        if action not in ("ALLOW", "BLOCK", "REJECT"):
            continue
        src_cov = source_coverage(p.get("source") or {}, network, groups)
        if src_cov == NONE:
            continue
        dst = p.get("destination") or {}
        if (dst.get("matching_target") or "ANY").upper() in NON_PORT_TARGETS:
            # Matches by application, domain or country, not by DNS server:
            # it neither decides nor meaningfully covers a DNS path.
            continue
        d = dest_fn(dst)
        exceptions = None
        if isinstance(d, tuple):
            d, exceptions = d
        cov = _combine(
            src_cov, d, port_coverage(dst, port, groups), protocol_coverage(p, tcp, udp))
        sched = ((p.get("schedule") or {}).get("mode") or "ALWAYS").upper()
        if cov == FULL and sched != "ALWAYS":
            cov = PARTIAL
        if cov == NONE:
            continue
        ref = _rule_ref(p)
        if sched != "ALWAYS":
            ref["scheduled"] = True
        if cov == PARTIAL:
            # A BLOCK that is partial only because it targets some addresses
            # on every port is a general access rule, not DNS protection:
            # recording it would soften "Open" into "Partial" for no reason.
            general = (action != "ALLOW" and src_cov == FULL and d != FULL
                       and (dst.get("port_matching_type") or "ANY").upper() == "ANY")
            if not general:
                partial.append(ref)
            continue
        return {
            "decided": "ALLOW" if action == "ALLOW" else "BLOCK",
            "rule": ref, "partial": partial, "except": exceptions or [],
        }
    return {"decided": None, "rule": None, "partial": partial, "except": []}


# ---------------------------------------------------------------------------
# Per-network audit
# ---------------------------------------------------------------------------

def _who(ref: Dict) -> str:
    if ref.get("ours"):
        return f"House Arrest rule \"{ref['name']}\""
    if ref.get("predefined"):
        return f"UniFi's built-in rule \"{ref['name']}\""
    return f"your rule \"{ref['name']}\""


def _family_result(res: Dict) -> str:
    return {"BLOCK": "blocked", "ALLOW": "allowed"}.get(res["decided"], "allowed")


NO_V6 = {"decided": "NA", "rule": None, "partial": [], "except": []}


def _channel_from_walks(key: str, walks: Dict[str, Dict]) -> Dict:
    """Turn the v4/v6 walks for one path into a UI cell."""
    v4, v6 = walks["v4"], walks["v6"]
    v6_off = v6["decided"] == "NA"
    b4, b6 = v4["decided"] == "BLOCK", v6["decided"] in ("BLOCK", "NA")
    rules = []
    for w in (v4, v6):
        if w["rule"] and w["rule"]["id"] not in [r["id"] for r in rules]:
            rules.append(w["rule"])
    partial = []
    for w in (v4, v6):
        for r in w["partial"]:
            if r["id"] not in [x["id"] for x in partial]:
                partial.append(r)

    notes: List[str] = []
    leak = ("devices can still reach DNS servers on those networks over IPv6"
            if key == CH_LAN else
            "if your internet connection has IPv6, this still gets out")
    if b4 and b6:
        state, label = GOOD, "Blocked"
        if v6_off:
            notes.append(f"Blocked by {_who(v4['rule'])}. IPv6 is off on this "
                         "network, so IPv4 is the only way out.")
        elif v4["rule"]["id"] == v6["rule"]["id"]:
            notes.append(f"Blocked by {_who(v4['rule'])}.")
        else:
            notes.append(f"IPv4 blocked by {_who(v4['rule'])}; IPv6 by {_who(v6['rule'])}.")
    elif b4 and not b6:
        state, label = WARN, "IPv4 only"
        notes.append(f"IPv4 is blocked by {_who(v4['rule'])}, but IPv6 is not "
                     f"blocked: {leak}.")
    elif b6 and not b4 and not v6_off:
        state, label = BAD, "IPv6 only"
        notes.append(f"Only IPv6 is blocked (by {_who(v6['rule'])}); IPv4 gets out.")
    else:
        state, label = BAD, "Open"
        w = v4
        if w["rule"] and not w["rule"].get("predefined"):
            notes.append(f"Allowed by {_who(w['rule'])}, which runs before any block.")
        else:
            notes.append("Nothing blocks it.")
    exc = sorted(set(v4["except"]) | set(v6["except"]))
    if exc and (b4 or b6):
        notes.append("Except to " + ", ".join(exc) + " (allowed by that rule's own exception list).")
    blocks_before = [r for r in partial if r["action"] in ("BLOCK", "REJECT")]
    allows_before = [r for r in partial if r["action"] == "ALLOW"]
    if allows_before and (b4 or b6):
        notes.append("Some traffic is let through first by "
                     + "; ".join(_who(r) for r in allows_before)
                     + " (specific devices or destinations).")
    if blocks_before and state != GOOD:
        notes.append("Partly covered by " + "; ".join(_who(r) for r in blocks_before)
                     + " (specific devices, destinations or a schedule only).")
        if state == BAD:
            state, label = WARN, "Partial"
    return {"key": key, "label": CHANNEL_LABELS[key], "state": state,
            "value": label, "detail": " ".join(notes),
            "rules": rules, "partial_rules": partial,
            "v4": _family_result(v4),
            "v6": "n/a" if v6_off else _family_result(v6)}


def _doh_channel(ordered: List[Dict], network: Dict, groups: Dict[str, List[str]]) -> Dict:
    """
    DoH runs on 443 like all web traffic, so no port rule can tell it apart.
    UniFi can match it two ways: an APP destination (DPI), or an IP list of
    known DoH servers on 443. Both are reported as partial by nature.
    """
    found = []
    for p in ordered:
        if (p.get("action") or "").upper() not in ("BLOCK", "REJECT"):
            continue
        if not matches_new_connections(p):
            continue
        if source_coverage(p.get("source") or {}, network, groups) == NONE:
            continue
        dst = p.get("destination") or {}
        mt = (dst.get("matching_target") or "").upper()
        if mt in ("APP", "APP_CATEGORY"):
            found.append((p, "app"))
        elif mt == "IP" and (dst.get("port_matching_type") or "ANY").upper() != "ANY" \
                and port_coverage(dst, 443, groups) == FULL:
            found.append((p, "ip"))
    if not found:
        return {"key": CH_DOH, "label": CHANNEL_LABELS[CH_DOH], "state": NEUTRAL,
                "value": "Not blocked",
                "detail": ("No rule targets DNS-over-HTTPS. It runs on port 443 like "
                           "every website, so a port rule can't block it. UniFi can "
                           "with an app-based block rule (Policy Engine, application "
                           "matching), which House Arrest does not create."),
                "rules": [], "partial_rules": [], "v4": "allowed", "v6": "allowed"}
    apps = [_rule_ref(p) for p, how in found if how == "app"]
    lists = [_rule_ref(p) for p, how in found if how == "ip"]
    parts = []
    if apps:
        parts.append("Application-based block rules apply here: "
                     + "; ".join(_who(r) for r in apps)
                     + ". House Arrest can't read which applications a rule lists, "
                       "so check in UniFi that one of them names DNS-over-HTTPS.")
    if lists:
        parts.append("; ".join(_who(r) for r in lists)
                     + " blocks a list of server addresses on port 443. DoH "
                       "servers not on that list still work.")
    return {"key": CH_DOH, "label": CHANNEL_LABELS[CH_DOH], "state": NEUTRAL,
            "value": "Check in UniFi", "detail": " ".join(parts),
            "rules": [_rule_ref(p) for p, _ in found], "partial_rules": [],
            "v4": "blocked", "v6": "blocked"}


def resolver_summary(network: Dict, networks: List[Dict]) -> Dict:
    """What DHCP hands out, classified."""
    handed = P.dhcp_dns_of(network)
    gw = P.gateway_ips(networks)
    if not handed:
        return {"kind": "gateway", "servers": [], "label": "Gateway",
                "detail": "DHCP hands out the gateway (Auto)."}
    kinds = []
    for ip in handed:
        if ip in gw:
            kinds.append("gateway")
        elif any(P._ip_in_subnet(ip, n.get("ip_subnet")) for n in networks
                 if n.get("purpose") != "wan"):
            kinds.append("lan")
        else:
            kinds.append("internet")
    uniq = sorted(set(kinds))
    kind = uniq[0] if len(uniq) == 1 else "mixed"
    label = "Gateway (" + ", ".join(handed) + ")" if kind == "gateway" else ", ".join(handed)
    return {"kind": kind, "servers": handed, "label": label,
            "detail": "DHCP hands out " + ", ".join(handed) + "."}


def _zone_kind(zones: List[Dict], zid: Optional[str]) -> str:
    for z in zones or []:
        if z.get("_id") == zid:
            return ((z.get("zone_key") or "") or "").lower()
    return ""


def audit_network(
    network: Dict,
    networks: List[Dict],
    zones: List[Dict],
    policies: List[Dict],
    groups: Dict[str, List[str]],
    external_id: str,
    gateway_zone_id: Optional[str],
    interception: Dict,
) -> Dict:
    zid = P.zone_of_network(network, zones)
    ext = pair_policies(policies, zid, external_id)
    channels = []

    v6 = network_has_ipv6(network)

    def walks_for(ordered, port, tcp, udp, dest_fn):
        return {"v4": walk(ordered, network, "v4", port, tcp, udp, groups, dest_fn),
                "v6": (walk(ordered, network, "v6", port, tcp, udp, groups, dest_fn)
                       if v6 else NO_V6)}

    any_dst = lambda d: dest_coverage_any(d, groups)
    channels.append(_channel_from_walks(CH_DNS, walks_for(ext, 53, True, True, any_dst)))
    channels.append(_channel_from_walks(CH_DOT, walks_for(ext, 853, True, False, any_dst)))
    channels.append(_doh_channel(ext, network, groups))

    # DNS to other networks in the same zone. The gateway is its own zone
    # and other zones have their own pairs; same-subnet peers never pass the
    # gateway at all (stated, never "blocked").
    siblings = [n for n in networks
                if n.get("_id") != network.get("_id") and n.get("purpose") != "wan"
                and P.zone_of_network(n, zones) == zid and _subnet(n) is not None]
    if not siblings:
        channels.append({"key": CH_LAN, "label": CHANNEL_LABELS[CH_LAN],
                         "state": NEUTRAL, "value": "n/a",
                         "detail": "This is the only network in its zone. Other "
                                   "zones are separated by their own zone rules.",
                         "rules": [], "partial_rules": [], "v4": "n/a", "v6": "n/a"})
    else:
        lan = pair_policies(policies, zid, zid)
        subs = [_subnet(n) for n in siblings]
        sub_dst = lambda d: dest_coverage_subnets(d, subs, groups)
        ch = _channel_from_walks(CH_LAN, walks_for(lan, 53, True, True, sub_dst))
        names = ", ".join(n.get("name") or "network" for n in siblings)
        ch["detail"] = f"To {names}: " + ch["detail"]
        channels.append(ch)

    resolver = resolver_summary(network, networks)

    # Is the resolver DHCP hands out actually reachable? A block on internet
    # DNS with no allow for a handed-out public resolver means no DNS at all.
    problems: List[str] = []
    for ip in resolver["servers"]:
        if ip in P.gateway_ips(networks):
            target_pair = pair_policies(policies, zid, gateway_zone_id) if gateway_zone_id else []
        elif any(P._ip_in_subnet(ip, n.get("ip_subnet")) for n in networks if n.get("purpose") != "wan"):
            if P._ip_in_subnet(ip, network.get("ip_subnet")):
                continue                    # same subnet: never passes the gateway
            home = next(n for n in networks if n.get("purpose") != "wan"
                        and P._ip_in_subnet(ip, n.get("ip_subnet")))
            target_pair = pair_policies(policies, zid, P.zone_of_network(home, zones))
        else:
            target_pair = ext
        res = walk(target_pair, network, "v4", 53, True, True, groups,
                   lambda d, ip=ip: dest_coverage_ip(d, ip, groups))
        if res["decided"] == "BLOCK":
            problems.append(f"DHCP tells devices to use {ip}, but {_who(res['rule'])} "
                            "blocks DNS to it. Devices here may have no working DNS.")

    gw_notes = []
    if interception.get("encrypted_dns"):
        gw_notes.append("Encrypted DNS is on: the gateway sends lookups to its own "
                        "encrypted DNS servers.")
    if network.get("_id") in interception.get("content_filtered", []):
        gw_notes.append("CyberSecure Content Filter redirects this network's DNS.")
    if interception.get("ad_blocking"):
        gw_notes.append("Ad Blocking filters DNS at the gateway.")

    no_internet = network.get("internet_access_enabled") is False
    states = [c["state"] for c in channels if c["key"] in (CH_DNS, CH_DOT)]
    if problems:
        verdict = (BAD, "DNS broken?", " ".join(problems))
    elif all(s == GOOD for s in states):
        verdict = (GOOD, "Locked", "Devices can only use the DNS server DHCP hands out"
                   + (" (or the gateway)." if resolver["kind"] != "gateway" else "."))
    elif any(s == GOOD for s in states) or WARN in states:
        verdict = (WARN, "Partly locked", "Some DNS paths to the internet are still open.")
    else:
        verdict = (BAD, "Open", "Devices here can use any DNS server on the internet.")

    return {
        "id": network.get("_id"),
        "name": network.get("name") or "(unnamed)",
        "vlan": P.vlan_id(network.get("vlan")),
        "zone_id": zid,
        "zone_name": P.zone_name(zones, zid),
        "isolated": bool(network.get("network_isolation_enabled")),
        "internet": not no_internet,
        "resolver": resolver,
        "channels": channels,
        "gateway_notes": gw_notes,
        "problems": problems,
        "verdict": {"state": verdict[0], "label": verdict[1], "detail": verdict[2]},
    }


def audit(
    networks: List[Dict],
    zones: List[Dict],
    policies: List[Dict],
    firewall_groups: Optional[List[Dict]],
    interception: Optional[Dict] = None,
    ignored: Optional[List[str]] = None,
) -> Dict:
    groups = group_index(firewall_groups)
    external_id = P.find_zone_id(zones, "external")
    gateway_id = P.find_zone_id(zones, "gateway")
    rows = []
    for n in networks or []:
        if n.get("purpose") == "wan" or not n.get("ip_subnet"):
            continue
        if not P.zone_of_network(n, zones):
            continue
        rows.append(audit_network(n, networks, zones, policies, groups,
                                  external_id, gateway_id, interception or {}))
    rows.sort(key=lambda r: (r["zone_name"], r["vlan"] is None, r["vlan"] or 0))
    ignored = [i for i in (ignored or []) if i]
    return {"rows": rows,
            "suggestions": suggest(rows, networks, zones, policies, ignored),
            "styles": STYLES, "ignored": ignored}


# ---------------------------------------------------------------------------
# Suggestions
# ---------------------------------------------------------------------------

def _zone_source(zone_id: str) -> Dict:
    """Every device in the zone - the shape UniFi itself writes for "Any"."""
    return {"matching_target": "ANY", "match_opposite_ports": False,
            "port_matching_type": "ANY", "zone_id": zone_id}


def _ip_source(ips: List[str], zone_id: str) -> Dict:
    """Specific source addresses (shape read off UniFi's own Return rules)."""
    return {"matching_target": "IP", "matching_target_type": "SPECIFIC",
            "ips": list(ips), "match_opposite_ips": False,
            "match_opposite_ports": False, "port_matching_type": "ANY",
            "zone_id": zone_id}


def _gap(row: Dict, key: str) -> Optional[str]:
    """'both' | 'v6' | 'v4' | None - which IP families still need a block."""
    ch = next((c for c in row["channels"] if c["key"] == key), None)
    if not ch or ch["v4"] == "n/a":
        return None
    need4 = ch["v4"] != "blocked"
    need6 = ch["v6"] not in ("blocked", "n/a")
    if need4 and ch["v6"] == "n/a":
        # IPv6 is off today; write the rule for both so switching it on
        # later does not silently open a path.
        return "both"
    if need4 and need6:
        return "both"
    if need6:
        return "v6"
    if need4:
        return "v4"
    return None


_IPV = {"both": "BOTH", "v4": "IPV4", "v6": "IPV6"}


def suggest(rows: List[Dict], networks: List[Dict], zones: List[Dict],
            policies: List[Dict], ignored: Optional[List[str]] = None) -> List[Dict]:
    """
    Gap-filling rule sets, one per (zone, path, IP-family need), in BOTH
    styles. Payloads carry index 0; apply re-reads the console and assigns
    real indexes, so a suggestion can never be applied stale.

    `ignored` networks are ones the user said not to touch (a work laptop
    that breaks under DNS blocks). They never get a per-network rule, and a
    zone that holds one gets no zone-wide rule either, since that rule would
    cover it anyway.
    """
    skip = set(ignored or [])
    out: List[Dict] = []
    gw = P.gateway_ips(networks)
    by_id = {n.get("_id"): n for n in networks or []}
    external_id = P.find_zone_id(zones, "external")
    zone_rows: Dict[str, List[Dict]] = {}
    for r in rows:
        zone_rows.setdefault(r["zone_id"], []).append(r)

    for zid, zrows in zone_rows.items():
        zname = P.zone_name(zones, zid)
        all_in_zone = [r for r in zrows]

        # LAN resolvers living on a network in this zone that other networks
        # hand out: blocking that network's internet DNS would cut the
        # resolver's own upstream, so it gets an allow first.
        lan_resolver_ips = []
        for r in rows:
            for ip in r["resolver"]["servers"]:
                if ip in gw:
                    continue
                for z in zrows:
                    if P._ip_in_subnet(ip, by_id.get(z["id"], {}).get("ip_subnet")) \
                            and ip not in lan_resolver_ips:
                        lan_resolver_ips.append(ip)

        paths = (
            # key, port, title, destination zone, where, needs internet
            (CH_DNS, P.DNS_PORT, "Block DNS to the internet", external_id, "the internet", True),
            (CH_DOT, P.DOT_PORT, "Block DNS-over-TLS", external_id, "the internet", True),
            (CH_LAN, P.DNS_PORT, "Block DNS to other networks", zid,
             f"other networks in the {zname} zone", False),
        )
        for key, port, title, dst_zone, where, needs_internet in paths:
            needs: Dict[str, List[Dict]] = {}
            for r in zrows:
                if needs_internet and not r["internet"]:
                    continue
                if r["id"] in skip:
                    continue
                g = _gap(r, key)
                if g:
                    needs.setdefault(g, []).append(r)
            for need, gap_rows in needs.items():
                # Allows that must precede the block so nothing loses DNS.
                allows = []         # (name, source-kind, dest ips or None, why)
                if key == CH_DNS:
                    public = []
                    for r in gap_rows:
                        for ip in r["resolver"]["servers"]:
                            if ip not in gw and not any(
                                    P._ip_in_subnet(ip, n.get("ip_subnet"))
                                    for n in networks if n.get("purpose") != "wan") \
                                    and ip not in public:
                                public.append(ip)
                    if public:
                        allows.append(("allow DHCP DNS servers", "src", public,
                                       f"Allows {', '.join(public)} first, because DHCP "
                                       "hands it out and devices would lose DNS without it."))
                    if lan_resolver_ips:
                        allows.append(("allow LAN DNS server upstream", "resolver", None,
                                       f"Lets the DNS server {', '.join(lan_resolver_ips)} "
                                       "keep looking names up on the internet."))
                elif key == CH_LAN and lan_resolver_ips:
                    allows.append(("allow LAN DNS servers", "src", list(lan_resolver_ips),
                                   f"Allows {', '.join(lan_resolver_ips)} first, because "
                                   "DHCP hands it out on this zone's networks."))
                fam = {"both": "", "v4": " (IPv4)", "v6": " (IPv6)"}[need]
                for style in (STYLE_NETWORK, STYLE_ZONE):
                    if style == STYLE_ZONE and any(r["id"] in skip for r in all_in_zone):
                        continue
                    covered = gap_rows if style == STYLE_NETWORK else all_in_zone
                    label = (", ".join(r["name"] for r in gap_rows)
                             if style == STYLE_NETWORK else f"{zname} zone")
                    src = (P.network_source([r["id"] for r in gap_rows], zid)
                           if style == STYLE_NETWORK else _zone_source(zid))
                    pols, why = [], []
                    for aname, kind, ips, text in allows:
                        pols.append(_suggested(P._base_policy(
                            name=f"House Arrest DNS: {label} - {aname}",
                            action="ALLOW", index=0,
                            source=(_ip_source(lan_resolver_ips, zid)
                                    if kind == "resolver" else src),
                            destination=P._dns_dest(dst_zone, P.DNS_PORT, ips),
                            description=P.describe_dns(
                                f"{aname.capitalize()} for {label}")), need))
                        why.append(text)
                    pols.append(_suggested(P._base_policy(
                        name=f"House Arrest DNS: {label} - {title}{fam}",
                        action="BLOCK", index=0, source=src,
                        destination=P._dns_dest(dst_zone, port),
                        description=P.describe_dns(f"DNS lockdown for {label}")), need))
                    why.insert(0, ("Blocks port " + port + fam + " from "
                                   + (", ".join(r["name"] for r in gap_rows)
                                      if style == STYLE_NETWORK else
                                      f"every network in the {zname} zone")
                                   + f" to {where}."))
                    out.append({
                        "id": f"{style}:{zid}:{key}:{need}",
                        "style": style, "zone_id": zid, "zone_name": zname,
                        "channel": key, "family": need,
                        "title": title + fam + (f" for {label}" if style == STYLE_NETWORK
                                                else f" for the {zname} zone"),
                        "networks": [r["name"] for r in covered],
                        "fills": [r["name"] for r in gap_rows],
                        "fill_ids": [r["id"] for r in gap_rows],
                        "why": why, "label": label, "policies": pols,
                        "improves": _improves(gap_rows, key),
                    })
    return out


def _suggested(policy: Dict, need: str) -> Dict:
    policy["ip_version"] = _IPV[need]
    return policy


def _improves(gap_rows: List[Dict], key: str) -> List[str]:
    """Plain advice about the user's own rules this suggestion complements."""
    tips = []
    for r in gap_rows:
        ch = next((c for c in r["channels"] if c["key"] == key), None)
        if not ch:
            continue
        for ref in ch["rules"]:
            if ref["action"] == "BLOCK" and ref["ip_version"] == "IPV4" \
                    and not ref["predefined"] and not ref["ours"]:
                tip = (f"Your rule \"{ref['name']}\" is IPv4 only. Alternative: "
                       "edit it in UniFi and set IP Version to Both, instead of "
                       "adding this rule.")
                if tip not in tips:
                    tips.append(tip)
    return tips
