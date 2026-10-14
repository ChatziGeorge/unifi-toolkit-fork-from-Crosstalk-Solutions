"""
Rule check: a quick look at every custom firewall rule. Is it OK, can it be
improved, does it clash with other rules?

Works on any console: it reads the rules, zones, networks and groups the
controller reports and never relies on rule names except for one clearly
labelled hint (similar rules in other zones). Nothing here writes anything.

Severities:
  issue    - the rule does not do what it looks like it does
  improve  - it works, but could be tighter or more consistent
  info     - worth knowing; not a problem by itself
"""
from typing import Dict, List, Optional, Tuple
import re

from tools.house_arrest import dns_audit as A
from tools.house_arrest import policies as P

ISSUE, IMPROVE, INFO = "issue", "improve", "info"

# Fields that define WHAT a side of a rule matches (not ids or display data).
_SIDE_KEYS = ("matching_target", "matching_target_type", "ips", "ip_group_id",
              "network_ids", "client_macs", "app_ids", "app_category_ids",
              "web_domains", "regions", "match_opposite_ips",
              "match_opposite_networks", "port_matching_type", "port",
              "port_group_id", "match_opposite_ports")


def _side_key(side: Dict) -> Tuple:
    out = []
    for k in _SIDE_KEYS:
        v = side.get(k)
        if isinstance(v, list):
            v = tuple(sorted(str(x) for x in v))
        out.append((k, v))
    return tuple(out)


def _match_key(p: Dict) -> Tuple:
    """Everything that decides which traffic a rule matches."""
    return (
        _side_key(p.get("source") or {}),
        _side_key(p.get("destination") or {}),
        (p.get("protocol") or "all").lower(),
        bool(p.get("match_opposite_protocol")),
        (p.get("ip_version") or "BOTH").upper(),
        (p.get("connection_state_type") or "ALL").upper(),
        tuple(sorted(p.get("connection_states") or [])),
        ((p.get("schedule") or {}).get("mode") or "ALWAYS").upper(),
    )


def _side_is_any(side: Dict) -> bool:
    return (side.get("matching_target") or "ANY").upper() == "ANY"


def _ports_any(side: Dict) -> bool:
    return (side.get("port_matching_type") or "ANY").upper() == "ANY" \
        and not side.get("match_opposite_ports")


def _ports_of(side: Dict) -> Tuple:
    return (side.get("port_matching_type"), side.get("port"),
            side.get("port_group_id"), bool(side.get("match_opposite_ports")))


def covers(e: Dict, r: Dict) -> bool:
    """
    Does earlier rule `e` match ALL the traffic rule `r` matches?

    Conservative: only answers True when it can be sure (e is "any" on a
    side, or identical on it). A False is "not proven", never "no overlap".
    """
    ev = (e.get("ip_version") or "BOTH").upper()
    if ev != "BOTH" and ev != (r.get("ip_version") or "BOTH").upper():
        return False
    if ((e.get("schedule") or {}).get("mode") or "ALWAYS").upper() != "ALWAYS":
        return False
    ecs = (e.get("connection_state_type") or "ALL").upper()
    if ecs != "ALL" and (ecs, tuple(sorted(e.get("connection_states") or []))) != \
            ((r.get("connection_state_type") or "ALL").upper(),
             tuple(sorted(r.get("connection_states") or []))):
        return False
    ep = (e.get("protocol") or "all").lower()
    if e.get("match_opposite_protocol") or (ep != "all" and ep != (r.get("protocol") or "all").lower()):
        return False
    for side in ("source", "destination"):
        es, rs = e.get(side) or {}, r.get(side) or {}
        same_target = _side_is_any(es) or _side_key({k: v for k, v in es.items()
                                                     if k not in ("port_matching_type", "port",
                                                                  "port_group_id", "match_opposite_ports")}) \
            == _side_key({k: v for k, v in rs.items()
                          if k not in ("port_matching_type", "port", "port_group_id",
                                       "match_opposite_ports")})
        if not same_target:
            return False
        if not (_ports_any(es) or _ports_of(es) == _ports_of(rs)):
            return False
    return True


def _empty_objects(p: Dict, groups: Dict[str, List[str]], group_ids: set) -> List[str]:
    """Things in the rule that match nothing."""
    out = []
    for label, side in (("source", p.get("source") or {}), ("destination", p.get("destination") or {})):
        mt = (side.get("matching_target") or "ANY").upper()
        if mt == "IP":
            gid = side.get("ip_group_id")
            if gid:
                if gid not in group_ids:
                    out.append(f"its {label} uses an address group that no longer exists")
                elif not groups.get(gid):
                    out.append(f"its {label} address group is empty")
            elif not side.get("ips"):
                out.append(f"its {label} IP list is empty")
        elif mt == "NETWORK" and not side.get("network_ids"):
            out.append(f"its {label} network list is empty")
        elif mt == "CLIENT" and not side.get("client_macs"):
            out.append(f"its {label} device list is empty")
        elif mt == "APP" and not side.get("app_ids"):
            out.append(f"its {label} application list is empty")
        pg = side.get("port_group_id")
        if (side.get("port_matching_type") or "").upper() == "OBJECT":
            if not pg or pg not in group_ids:
                out.append(f"its {label} uses a port group that no longer exists")
            elif not groups.get(pg):
                out.append(f"its {label} port group is empty")
    return out


_TAG = re.compile(r"^\s*(\[[^\]]+\]\s*)+")


def _title(name: str) -> str:
    """'[Internal] Block DoT' -> 'block dot'. Only used for the similar-rules hint."""
    return _TAG.sub("", name or "").strip().lower()


def check(policies: List[Dict], zones: List[Dict], networks: List[Dict],
          firewall_groups: Optional[List[Dict]]) -> Dict:
    groups = A.group_index(firewall_groups)
    group_ids = set(groups)
    znames = {z.get("_id"): z.get("name") or "zone" for z in zones or []}
    nets_by_zone: Dict[str, List[Dict]] = {}
    for n in networks or []:
        if n.get("purpose") == "wan":
            continue
        zid = P.zone_of_network(n, zones)
        if zid:
            nets_by_zone.setdefault(zid, []).append(n)

    def pair(p):
        return ((p.get("source") or {}).get("zone_id"), (p.get("destination") or {}).get("zone_id"))

    by_pair: Dict[Tuple, List[Dict]] = {}
    for p in policies or []:
        by_pair.setdefault(pair(p), []).append(p)
    for k in by_pair:
        by_pair[k].sort(key=lambda p: p.get("index") if isinstance(p.get("index"), int) else 0)

    custom = [p for p in policies or [] if not p.get("predefined")]
    findings: Dict[str, List[Dict]] = {}

    def add(p, sev, text):
        findings.setdefault(p.get("_id") or p.get("name"), []).append({"severity": sev, "text": text})

    for r in custom:
        rid = r.get("_id")
        enabled = r.get("enabled") is not False
        sz, dz = pair(r)
        if not enabled:
            add(r, INFO, "Disabled: it does nothing until switched back on.")

        for what in _empty_objects(r, groups, group_ids) if firewall_groups is not None else []:
            add(r, ISSUE, f"Matches nothing: {what}.")

        if enabled:
            for e in by_pair.get((sz, dz), []):
                if e is r:
                    break
                if e.get("enabled") is False:
                    continue
                if not isinstance(e.get("index"), int) or not isinstance(r.get("index"), int) \
                        or e["index"] >= r["index"]:
                    continue
                if not covers(e, r):
                    continue
                who = ("UniFi's built-in" if e.get("predefined") else "your rule") + f" \"{e.get('name')}\""
                same = (e.get("action") or "").upper() == (r.get("action") or "").upper()
                if same and _match_key(e) == _match_key(r):
                    add(r, IMPROVE, f"Duplicate of {who}, which runs first. One of them can go.")
                elif same:
                    add(r, IMPROVE, f"Redundant: {who} runs first and already does this.")
                else:
                    add(r, ISSUE, f"Never takes effect: {who} runs first and "
                                  f"{(e.get('action') or '').lower()}s the same traffic.")
                break

        action = (r.get("action") or "").upper()
        if action in ("BLOCK", "REJECT") and (r.get("ip_version") or "BOTH").upper() == "IPV4":
            v6 = [n.get("name", "").strip() for n in nets_by_zone.get(sz, []) if A.network_has_ipv6(n)]
            if v6:
                add(r, ISSUE, "IPv4 only, but IPv6 is on for " + ", ".join(v6)
                    + ": IPv6 traffic gets past it. Set IP Version to Both.")
            else:
                add(r, IMPROVE, "IPv4 only. Fine while IPv6 is off on this zone's networks; "
                                "set IP Version to Both so switching IPv6 on later doesn't open a gap.")

        if enabled and action == "ALLOW":
            ret_name = f"{r.get('name')} (Return)"
            for ret in by_pair.get((dz, sz), []):
                if ret.get("name") != ret_name:
                    continue
                for b in by_pair.get((dz, sz), []):
                    if b is ret:
                        break
                    if b.get("enabled") is False or (b.get("action") or "").upper() not in ("BLOCK", "REJECT"):
                        continue
                    if (b.get("connection_state_type") or "ALL").upper() != "ALL":
                        continue
                    if not (_side_is_any(b.get("source") or {}) or b.get("ip_group_id")
                            or (b.get("source") or {}).get("matching_target") == "IP"):
                        continue
                    add(r, INFO, f"Rule order: UniFi placed this rule's reply rule \"{ret_name}\" "
                                 f"after \"{b.get('name')}\". Listed for information only; "
                                 "it doesn't mean the rule fails.")
                    break

        # Only when the controller reports a count of 0: some rules carry no
        # count at all, and a missing number is not "never matched".
        if enabled and "hits" in r and r.get("hits") == 0:
            add(r, INFO, "No hits recorded: nothing has matched it so far.")

    # Similar rules in other zones ("compared to other rules"). Name-based,
    # so it is only a hint: rules called "[Zone] Same title" are compared.
    by_title: Dict[str, List[Dict]] = {}
    for r in custom:
        # Blocks only: a block that exists for some zones and not others is a
        # possible gap; a missing ALLOW is not.
        if (r.get("action") or "").upper() not in ("BLOCK", "REJECT"):
            continue
        t = _title(r.get("name"))
        if t:
            by_title.setdefault(t, []).append(r)
    zones_with_rules = {pair(r)[0] for r in custom}
    for t, rules in by_title.items():
        src_zones = {pair(r)[0] for r in rules}
        if len(src_zones) < 2:
            continue
        versions = {(r.get("ip_version") or "BOTH").upper() for r in rules}
        if len(versions) > 1:
            for r in rules:
                others = sorted({znames.get(pair(o)[0], "?") for o in rules
                                 if (o.get("ip_version") or "BOTH").upper() != (r.get("ip_version") or "BOTH").upper()})
                add(r, IMPROVE, f"Differs from its similar rules in {', '.join(others)}: "
                                f"this one is IP Version {(r.get('ip_version') or 'BOTH').title()}.")
        missing = sorted(znames.get(z, "?") for z in zones_with_rules - src_zones
                         if z in nets_by_zone and z not in (None,))
        if missing:
            add(rules[0], INFO, "Similar rules (same name after the [zone] tag) exist for "
                + ", ".join(sorted(znames.get(z, "?") for z in src_zones))
                + " but not for " + ", ".join(missing) + ". Check if that's intended.")

    rows = []
    for r in custom:
        f = findings.get(r.get("_id") or r.get("name"), [])
        worst = ISSUE if any(x["severity"] == ISSUE for x in f) else \
            IMPROVE if any(x["severity"] == IMPROVE for x in f) else \
            INFO if f else "ok"
        sz, dz = pair(r)
        rows.append({
            "id": r.get("_id"), "name": r.get("name"), "index": r.get("index"),
            "enabled": r.get("enabled") is not False, "action": r.get("action"),
            "ours": P.is_house_arrest(r),
            "pair": f"{znames.get(sz, '?')} → {znames.get(dz, '?')}",
            "status": worst, "findings": f,
        })
    order = {ISSUE: 0, IMPROVE: 1, INFO: 2, "ok": 3}
    rows.sort(key=lambda x: (x["pair"], x["index"] if isinstance(x["index"], int) else 0))

    unused = []
    if firewall_groups is not None:
        blob = " ".join(str(p) for p in policies or [])
        for g in firewall_groups:
            if g.get("_id") and g["_id"] not in blob:
                unused.append({"name": g.get("name") or "group", "type": g.get("group_type"),
                               "members": g.get("group_members") or []})

    counts = {k: sum(1 for x in rows if x["status"] == k) for k in (ISSUE, IMPROVE, INFO, "ok")}
    return {"rows": rows, "unused_groups": unused, "counts": counts,
            "groups_unreadable": firewall_groups is None}
