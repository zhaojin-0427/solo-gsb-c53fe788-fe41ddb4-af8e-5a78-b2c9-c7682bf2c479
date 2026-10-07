"""应答与变更模式的 JSON 序列化。"""
from __future__ import annotations

import dns.name
import dns.rdatatype
import dns.rdata

from .zone import ParsedZone, RR
from .resolver import Answer
from .diff import Pattern, Cone


def _name(name: dns.name.Name, origin: dns.name.Name) -> str:
    try:
        rel = name.relativize(origin)
        text = rel.to_text()
        return "@" if text in ("", "@") else text
    except Exception:
        return name.to_text()


def _rdata_to_json(rr: RR) -> dict:
    rd = rr.rdata
    if rr.rdtype == dns.rdatatype.SOA:
        return {
            "mname": rd.mname.to_text(),
            "rname": rd.rname.to_text(),
            "serial": rd.serial,
            "refresh": rd.refresh,
            "retry": rd.retry,
            "expire": rd.expire,
            "minimum": rd.minimum,
        }
    if rr.rdtype in (dns.rdatatype.NS,):
        return {"target": rd.target.to_text()}
    if rr.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME):
        return {"target": rd.target.to_text()}
    if rr.rdtype == dns.rdatatype.A:
        return {"address": rd.address}
    if rr.rdtype == dns.rdatatype.AAAA:
        return {"address": rd.address}
    return {"text": rd.to_text()}


def rr_to_json(rr: RR, origin: dns.name.Name) -> dict:
    return {
        "name": _name(rr.owner, origin),
        "type": dns.rdatatype.to_text(rr.rdtype),
        "ttl": rr.ttl,
        "rdata": _rdata_to_json(rr),
    }


def _section(rrs, origin: dns.name.Name) -> list[dict]:
    # 同属主同类型的记录合并展示为 rrset 风格，并保持确定顺序。
    groups: dict[tuple, list[RR]] = {}
    order: list[tuple] = []
    for rr in rrs:
        key = (tuple(rr.owner.labels), rr.rdtype)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(rr)
    out = []
    for key in order:
        g = groups[key]
        out.append({
            "name": _name(g[0].owner, origin),
            "type": dns.rdatatype.to_text(g[0].rdtype),
            "ttl": g[0].ttl,
            "records": [_rdata_to_json(x) for x in g],
        })
    return out


def answer_to_json(ans: Answer, origin: dns.name.Name) -> dict:
    return {
        "qname": _name(ans.qname, origin),
        "qtype": dns.rdatatype.to_text(ans.qtype),
        "rcode": ans.rcode,
        "aa": ans.aa,
        "termination": ans.termination,
        "answer": _section(ans.answer, origin),
        "authority": _section(ans.authority, origin),
        "additional": _section(ans.additional, origin),
        "wildcard_source": (
            _name(ans.wildcard_source, origin)
            if ans.wildcard_source is not None else None
        ),
        "dname_encloser": (
            _name(ans.dname_encloser, origin)
            if ans.dname_encloser is not None else None
        ),
        "alias_chain": [
            {
                "kind": h.kind,
                "owner": _name(h.owner, origin),
                "target": h.target.to_text(),
                "presented_cname_owner": _name(h.cname_owner, origin),
            }
            for h in ans.hops
        ],
    }


def cone_to_json(cone: Cone, origin: dns.name.Name) -> dict:
    return {
        "selector": cone.render(),
        "kind": cone.kind,
        "name": ".".join(cone.labels) if cone.labels else "@",
    }


def pattern_to_json(p: Pattern, origin: dns.name.Name) -> dict:
    return {
        "scope": cone_to_json(p.scope, origin),
        "exclude": [cone_to_json(c, origin) for c in p.exclude],
        "witness": {
            "name": _name(p.witness, origin),
            "probe_kind": p.witness_kind,
        },
        "baseline": answer_to_json(p.baseline, origin),
        "candidate": answer_to_json(p.candidate, origin),
    }
