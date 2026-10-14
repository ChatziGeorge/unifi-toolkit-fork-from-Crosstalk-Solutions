"""
Network-to-network reachability, read from the ordered policy list.

The Networks tab used to report isolation from one flag,
`network_isolation_enabled`. That flag is only one of the ways a network ends
up isolated: a Guest network in the Hotspot zone has the flag OFF and is
still cut off from every other network by the zone's built-in rules
(MEASURED 2026-10-14). Showing "Off" there was true about the flag and false
about the network.

A connection from network A to network B needs two things:
  * NEW traffic A -> B allowed, walked in the (zone A, zone B) pair, and
  * REPLIES B -> A allowed, walked in the (zone B, zone A) pair.

Same-network traffic never reaches the gateway and is not modelled here.
Everything is derived from rules, not from traffic: it says what the rules
allow, which is not a test.
"""
from typing import Dict, List, Optional

from tools.house_arrest import dns_audit as A
from tools.house_arrest import policies as P

OPEN, PARTIAL, BLOCKED = "open", "partial", "blocked"


def state_applies(policy: Dict, phase: str) -> bool:
    """Does this rule match NEW connections ("new") or reply traffic ("reply")?"""
    cst = (policy.get("connection_state_type") or "ALL").upper()
    if cst == "ALL":
        return True
    if cst == "RESPOND_ONLY":
        return phase == "reply"
    states = {str(s).upper() for s in policy.get("connection_states") or []}
    if phase == "new":
        return "NEW" in states
    return bool(states & {"ESTABLISHED", "RELATED"})


def any_port_coverage(side: Dict, groups: Dict[str, List[str]]) -> str:
    """For "all traffic": a rule limited to some ports only covers part of it."""
    spec = A._port_spec(side, groups)
    if spec is None:
        return A.PARTIAL
    neg, members = spec
    return A.FULL if not members and not neg else A.PARTIAL


def any_protocol_coverage(policy: Dict) -> str:
    proto = (policy.get("protocol") or "all").lower()
    if policy.get("match_opposite_protocol"):
        return A.PARTIAL
    return A.FULL if proto == "all" else A.PARTIAL


def walk_all(
    ordered: List[Dict],
    src_network: Dict,
    dst_subnet,
    family: str,
    phase: str,
    groups: Dict[str, List[str]],
    dst_network_id: Optional[str] = None,
) -> Dict:
    """First rule that fully decides ALL traffic from src_network to dst_subnet."""
    partial: List[Dict] = []
    for p in ordered:
        if not A.family_applies(p, family) or not state_applies(p, phase):
            continue
        action = (p.get("action") or "").upper()
        if action not in ("ALLOW", "BLOCK", "REJECT"):
            continue
        dst = p.get("destination") or {}
        if (dst.get("matching_target") or "ANY").upper() in A.NON_PORT_TARGETS:
            continue
        if phase == "reply" and (dst.get("port_matching_type") or "ANY").upper() != "ANY":
            continue
        src_cov = A.source_coverage(p.get("source") or {}, src_network, groups)
        if src_cov == A.NONE:
            continue
        d = A.dest_coverage_subnets(dst, [dst_subnet], groups,
                                    [dst_network_id] if dst_network_id else None)
        cov = A._combine(src_cov, d, any_port_coverage(dst, groups), any_protocol_coverage(p))
        sched = ((p.get("schedule") or {}).get("mode") or "ALWAYS").upper()
        if cov == A.FULL and sched != "ALWAYS":
            cov = A.PARTIAL
        if cov == A.NONE:
            continue
        ref = A._rule_ref(p)
        if cov == A.PARTIAL:
            if not (phase == "reply" and action == "ALLOW"):
                partial.append(ref)
            continue
        return {"decided": "ALLOW" if action == "ALLOW" else "BLOCK",
                "rule": ref, "partial": partial}
    return {"decided": None, "rule": None, "partial": partial}


def reach(a: Dict, b: Dict, zones: List[Dict], policies: List[Dict],
          groups: Dict[str, List[str]]) -> Dict:
    """
    Can devices on network `a` open connections to devices on network `b`?

    Returns {"state": open|partial|blocked, "by": deciding rule ref,
             "via": "outbound"|"replies"|None, "openings": [allow refs that
             let SOME traffic through], "unknown": bool}.
    """
    za, zb = P.zone_of_network(a, zones), P.zone_of_network(b, zones)
    sa, sb = A._subnet(a), A._subnet(b)
    if not (za and zb and sa and sb):
        return {"state": PARTIAL, "by": None, "via": None, "openings": [],
                "unknown": True}
    families = ["v4"]
    if A.network_has_ipv6(a) and A.network_has_ipv6(b):
        families.append("v6")

    rank = {BLOCKED: 0, PARTIAL: 1, OPEN: 2}
    best = None
    for fam in families:
        out = walk_all(A.pair_policies(policies, za, zb), a, sb, fam, "new", groups,
                       b.get("_id"))
        out_allows = [r for r in out["partial"] if r["action"] == "ALLOW"]
        out_blocks = [r for r in out["partial"] if r["action"] != "ALLOW"]
        if out["decided"] == "BLOCK":
            res = {"state": PARTIAL if out_allows else BLOCKED, "by": out["rule"],
                   "via": "outbound", "openings": out_allows}
        else:
            back = walk_all(A.pair_policies(policies, zb, za), b, sa, fam, "reply", groups,
                            a.get("_id"))
            if back["decided"] == "BLOCK":
                res = {"state": PARTIAL if out_allows else BLOCKED, "by": back["rule"],
                       "via": "replies", "openings": out_allows}
            else:
                res = {"state": PARTIAL if out_blocks else OPEN, "by": out["rule"],
                       "via": None, "openings": out_allows}
        if best is None or rank[res["state"]] > rank[best["state"]]:
            best = res
    best["unknown"] = False
    return best


def _entry(peer: str, direction: str, r: Dict) -> Dict:
    """
    Classify one direction to/from one peer network.

      blocked  - nothing gets through
      default  - open because nothing blocks it (UniFi's allow-all, or a
                 decision that never reached a block)
      rule     - blocked by default, but a rule opens it (fully or partly)
      builtin  - only UniFi's own built-in rules open it (e.g. Allow Public DNS)
    """
    e = {"peer": peer, "dir": direction, "kind": "blocked", "full": False, "rules": [],
         "blocked_by": None, "blocked_builtin": False}
    by = r.get("by")
    if by and r["state"] in (BLOCKED, PARTIAL) and by.get("action") in ("BLOCK", "REJECT"):
        e["blocked_by"] = by["name"]
        e["blocked_builtin"] = bool(by.get("predefined"))
    if r["state"] == BLOCKED:
        return e
    if r.get("unknown"):
        e["kind"] = "default"
        return e
    if r["state"] == OPEN:
        by = r.get("by")
        if not by or by.get("predefined"):
            e["kind"] = "default"
        else:
            e.update(kind="rule", full=True, rules=[by["name"]])
        return e
    openings = r.get("openings") or []
    if not openings:
        e["kind"] = "default"          # mostly open; a narrow block cuts part of it
        return e
    names = sorted({o["name"] for o in openings})
    builtin = all(o.get("predefined") for o in openings)
    e.update(kind="builtin" if builtin else "rule", rules=names)
    return e


def isolation_summary(network: Dict, networks: List[Dict], zones: List[Dict],
                      policies: List[Dict], firewall_groups: Optional[List[Dict]]) -> Dict:
    """Per peer network, in both directions: blocked, open by default, or opened by a rule."""
    groups = A.group_index(firewall_groups)
    others = [n for n in networks or []
              if n.get("_id") != network.get("_id") and n.get("purpose") != "wan"
              and n.get("ip_subnet")]
    entries = []
    for m in others:
        name = (m.get("name") or "network").strip()
        entries.append(_entry(name, "to", reach(network, m, zones, policies, groups)))
        entries.append(_entry(name, "from", reach(m, network, zones, policies, groups)))
    return {"entries": entries, "groups_unreadable": firewall_groups is None}


def _how(e: Dict) -> str:
    """What gets through, and why - without the peer name, so peers can be grouped."""
    if e["kind"] == "default":
        return "everything; nothing blocks it"
    quoted = ", ".join(f"\"{n}\"" for n in e["rules"])
    if e["kind"] == "builtin":
        what = "DNS queries only" if all("DNS" in n for n in e["rules"]) else "some traffic"
        return f"{what}, through UniFi's built-in {quoted}"
    if e["full"]:
        return f"everything, through your rule {quoted}"
    return f"some devices or ports, through {quoted}"


def _grouped(entries: List[Dict]) -> str:
    """'LAN, IoT (DNS queries only, ...); Printer (everything, ...)'."""
    order: List[str] = []
    peers: Dict[str, List[str]] = {}
    for e in entries:
        how = _how(e)
        if how not in peers:
            order.append(how)
            peers[how] = []
        peers[how].append(e["peer"])
    return "; ".join(f"{', '.join(peers[h])} ({h})" for h in order)


def _kept_apart(entries: List[Dict]) -> str:
    """
    Which rules keep this network apart from the others, grouped by rule:
    'your rule "Block Inter-VLAN Communication" (to LAN, from IoT); UniFi's
    built-in "Isolated Networks" (to Work)'. Works for any rule, whatever it
    is called: it names the rule that actually decides each blocked pair.
    """
    by_rule: Dict[tuple, Dict[str, set]] = {}
    for e in entries:
        if not e.get("blocked_by"):
            continue
        key = (e["blocked_by"], e["blocked_builtin"])
        by_rule.setdefault(key, {}).setdefault(e["peer"], set()).add(e["dir"])
    parts = []
    for (name, builtin), peers in by_rule.items():
        where = []
        for peer, dirs in peers.items():
            where.append(f"{peer} (both ways)" if len(dirs) == 2
                         else ("to " if "to" in dirs else "from ") + peer)
        who = f"UniFi's built-in \"{name}\"" if builtin else f"your rule \"{name}\""
        parts.append(f"{who} ({', '.join(where)})")
    return "; ".join(parts)


def isolation_cell(summary: Dict, flag_on: bool) -> Dict:
    """
    The Network isolation cell, from the rules rather than from the flag.

      Isolated / Isolated by zone (green) - nothing gets in or out
        ... "*"   - except a narrow opening made only by UniFi's OWN built-in
                    rules, named on its own line (user request)
      Partial  (amber) - blocked by default, but YOUR rules open paths
      Off      (grey)  - open by default

    Every hover also names the rules that do the blocking ("Kept apart by"),
    so isolation that comes from a hand-made rule such as an inter-VLAN block
    is visible, not only the isolation setting.
    """
    entries = summary["entries"]
    open_by_default = [e for e in entries if e["kind"] == "default"]
    by_rule = [e for e in entries if e["kind"] == "rule"]
    builtin = [e for e in entries if e["kind"] == "builtin"]
    setting = f"Isolation setting: {'On' if flag_on else 'Off'}."
    kept = _kept_apart(entries)
    kept_line = f"Kept apart by: {kept}." if kept else ""
    footer = "Worked out from the firewall rules in order; not a traffic test."
    if summary.get("groups_unreadable"):
        footer += " Port and address groups couldn't be read, so some answers may be too cautious."

    if not open_by_default and not by_rule:
        base = "Isolated" if flag_on else "Isolated by zone"
        parts = [setting, "Nothing on your other networks can reach this one, and it "
                 "can't reach them" + ("" if flag_on else ", because this zone's "
                 "firewall rules block it") + "."]
        label = base
        if builtin:
            label = base + " *"
            for how, peers in _builtin_groups(builtin):
                parts.append("* One exception, made by UniFi itself, not by your rules: "
                             + how + " " + ", ".join(peers) + ". " + _builtin_advice(builtin))
        if kept_line:
            parts.append(kept_line)
        parts.append(footer)
        return {"state": "good", "label": label, "text": " ".join(parts)}

    state, label = (("neutral", "Off") if open_by_default else ("warn", "Partial"))
    parts = [setting]
    inbound = [e for e in entries if e["dir"] == "from" and e["kind"] != "blocked"]
    outbound = [e for e in entries if e["dir"] == "to" and e["kind"] != "blocked"]
    parts.append("Can reach this network: " + (_grouped(inbound) if inbound else "nothing") + ".")
    parts.append("This network can reach: " + (_grouped(outbound) if outbound else "nothing") + ".")
    if kept_line:
        parts.append(kept_line)
    parts.append(footer)
    return {"state": state, "label": label, "text": " ".join(parts)}


def _builtin_groups(entries: List[Dict]) -> List:
    """[(how, [peers])] for built-in openings, phrased by direction."""
    out: Dict[str, List[str]] = {}
    for e in entries:
        dns = all("DNS" in n for n in e["rules"])
        names = ", ".join(f"\"{n}\"" for n in e["rules"])
        if e["dir"] == "to":
            how = (f"its built-in {names} rule lets devices here send DNS queries "
                   "(port 53) to devices on" if dns else
                   f"its built-in {names} rule lets some traffic from here reach")
        else:
            how = (f"its built-in {names} rule lets DNS queries (port 53) in from" if dns
                   else f"its built-in {names} rule lets some traffic in from")
        out.setdefault(how, []).append(e["peer"])
    return list(out.items())


def _builtin_advice(entries: List[Dict]) -> str:
    if all(all("DNS" in n for n in e["rules"]) for e in entries):
        return ("Everything else is blocked. This only matters if a device there "
                "runs a DNS server. To close it, add your own block rule for port "
                "53 between these zones; your own rules run before UniFi's "
                "built-in ones.")
    return "Everything else is blocked."
