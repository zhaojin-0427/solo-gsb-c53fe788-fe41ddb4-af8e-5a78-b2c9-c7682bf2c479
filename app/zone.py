"""BIND 文本解析与区域校验。

仅接受 SOA / NS / A / AAAA / CNAME / DNAME 以及 ``$ORIGIN`` / ``$TTL``
两个指令。任何非法记录、越区名称或外部引用（NS/CNAME/DNAME 的目标
位于区域之外）都会以 :class:`ZoneError` 让整单失败。

之所以不直接使用 ``dns.zone.from_text``，是因为它在 ``check_origin=False``
时会**静默丢弃**越区记录，无法满足“越区整单报错”；因此这里基于
dnspython 的 tokenizer 与 rdata 工厂自行逐行解析，全程自行追踪
``$ORIGIN``、``$TTL``、括号续行与缺省属主。
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.name
import dns.node
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.tokenizer
import dns.ttl

ALLOWED_RDTYPES = {
    dns.rdatatype.SOA,
    dns.rdatatype.NS,
    dns.rdatatype.A,
    dns.rdatatype.AAAA,
    dns.rdatatype.CNAME,
    dns.rdatatype.DNAME,
}
RDTYPE_NAMES = {
    dns.rdatatype.SOA: "SOA",
    dns.rdatatype.NS: "NS",
    dns.rdatatype.A: "A",
    dns.rdatatype.AAAA: "AAAA",
    dns.rdatatype.CNAME: "CNAME",
    dns.rdatatype.DNAME: "DNAME",
}
_DIRECTIVES = {"$ORIGIN", "$TTL", "$INCLUDE"}


class ZoneError(ValueError):
    """区域文本不合法或违反越区 / 外部引用约束。"""


def _owner_is_wildcard(name: dns.name.Name) -> bool:
    """属主是否为通配节点（最左标签为 ``*``，如 ``*.p``）。"""
    return len(name.labels) >= 2 and name.labels[0] == b"*"


@dataclass(frozen=True)
class RR:
    owner: dns.name.Name
    rdtype: int
    ttl: int
    rdata: dns.rdata.Rdata


@dataclass
class ParsedZone:
    origin: dns.name.Name
    records: list[RR]
    rrsets: dict[dns.name.Name, dict[int, list[RR]]] = field(default_factory=dict)
    # 空非终结点（empty non-terminal）：自身无任何 RRset，但作为某个
    # **普通**属主的严格祖先而存在的结构点。它们没有叶子下级的“存在”
    # 语义，却参与最近包围名 / 通配源 / NODATA 判定。
    nonterminals: set[dns.name.Name] = field(default_factory=set)
    # 通配父节点：通配属主 *.p 的父节点 p。RFC 4592 附录 A.1.1 把 p 视为
    # 区域树中存在的节点（x.p 的最近包围名即 p，故 *.p 能命中 x.p），但
    # p 自身在没有任何普通数据/普通后代时被查询仍是 NXDOMAIN——它与
    # nonterminals（真实空非终结点）是两种不同的“存在”。
    wildcard_parents: set[dns.name.Name] = field(default_factory=set)
    soa: RR | None = None

    def rdatasets(self, owner: dns.name.Name) -> dict[int, list[RR]]:
        return self.rrsets.get(owner, {})

    def has(self, owner: dns.name.Name) -> bool:
        return owner in self.rrsets

    def is_nonterminal(self, owner: dns.name.Name) -> bool:
        return owner in self.nonterminals

    def enclosing_exists(self, owner: dns.name.Name) -> bool:
        """名称能否作为最近包围名（路径上的存在节点）。

        以下三者都算：拥有普通 RRset 的属主、真实空非终结点、通配属主的
        父节点（RFC 4592 A.1.1）。通配属主本身（``*.p``）不作为普通查询
        名路径上的包围名。
        """
        if owner in self.rrsets:
            return not _owner_is_wildcard(owner)
        return owner in self.nonterminals or owner in self.wildcard_parents


# ---------------------------------------------------------------------------
# 逻辑行（处理括号续行与注释）
# ---------------------------------------------------------------------------

def _logical_lines(text: str, label: str):
    """产出 (lineno, 逻辑行, 行首是否为空白)。

    括号合并后的逻辑行保留“首行是否以空白起始”的信息，用于 BIND 的
    缺省属主（续行）判定；返回的文本本身已 strip。
    """
    buf = ""
    start_line = 1
    depth = 0
    continuation = False
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(";", 1)[0]
        leading_ws = bool(line) and line[0] in (" ", "\t")
        if depth == 0:
            start_line = i
            buf = line
            continuation = leading_ws
        else:
            buf += " " + line
        depth += line.count("(") - line.count(")")
        if depth < 0:
            raise ZoneError(f"{label}: 第 {i} 行括号不匹配（多余的 ')'）")
        if depth == 0 and buf.strip():
            yield start_line, buf.strip(), continuation
    if depth != 0:
        raise ZoneError(f"{label}: 第 {start_line} 行起括号未闭合")


def _tokens(line: str):
    return dns.tokenizer.Tokenizer(line)


# ---------------------------------------------------------------------------
# 主解析
# ---------------------------------------------------------------------------

def parse_zone(text: str, origin_text: str | None, *, label: str) -> ParsedZone:
    if not isinstance(text, str) or not text.strip():
        raise ZoneError(f"{label}: 区域文本为空")

    initial_origin = None
    if origin_text is not None:
        try:
            initial_origin = dns.name.from_text(origin_text.strip())
        except Exception as exc:
            raise ZoneError(f"{label}: origin 非法: {origin_text!r} ({exc})")

    origin = initial_origin
    default_ttl: int | None = None
    last_owner: dns.name.Name | None = None
    raw_records: list[tuple[dns.name.Name, int, int, dns.rdata.Rdata, int]] = []

    for lineno, line, leading_ws in _logical_lines(text, label):
        tok = _tokens(line)
        first = tok.get()
        if first.ttype == 0:
            continue

        token_value = first.value.upper() if hasattr(first, "value") else ""
        if token_value in _DIRECTIVES:
            if token_value == "$INCLUDE":
                raise ZoneError(f"{label}: 第 {lineno} 行不允许 $INCLUDE")
            nxt = tok.get()
            if nxt.ttype == 0:
                raise ZoneError(
                    f"{label}: 第 {lineno} 行 {token_value} 缺少参数"
                )
            arg = nxt.value
            try:
                if token_value == "$ORIGIN":
                    new_origin = dns.name.from_text(arg)
                    if not new_origin.is_absolute():
                        raise ZoneError(
                            f"{label}: 第 {lineno} 行 $ORIGIN 必须是绝对名"
                        )
                    origin = new_origin
                else:
                    default_ttl = dns.ttl.from_text(arg)
            except ZoneError:
                raise
            except Exception as exc:
                raise ZoneError(
                    f"{label}: 第 {lineno} 行 {token_value} 参数非法: {arg} ({exc})"
                ) from None
            if tok.get().ttype != 0:
                raise ZoneError(
                    f"{label}: 第 {lineno} 行 {token_value} 后有多余内容"
                )
            continue

        # --- 属主：行首为空白表示沿用上一属主（BIND 续行语义）---
        rest = [t for t in tok.get_remaining() if t.ttype != 0]
        if leading_ws:
            if last_owner is None:
                raise ZoneError(f"{label}: 第 {lineno} 行缺少属主名")
            owner = last_owner
            # 续行首 token（如 IN/TTL/类型）仍属于字段区。
            toks = [first] + rest
            idx = 0
        else:
            owner = _read_name_token(first, origin, label, lineno)
            last_owner = owner
            toks = rest
            idx = 0

        if origin is None:
            raise ZoneError(
                f"{label}: 第 {lineno} 行在 $ORIGIN/SOA 之前使用了名称 {owner}"
            )

        # --- TTL / class / type（class 可省；type 之后或遇到 '(' 全部为 RDATA）---
        ttl: int | None = None
        rdclass = dns.rdataclass.IN
        rdtype: int | None = None
        seen = set()
        while idx < len(toks):
            word = toks[idx].value
            if word == "(":
                break
            up = word.upper()
            if _is_type(up):
                rdtype = dns.rdatatype.from_text(up)
                idx += 1
                break
            if word in seen:
                raise ZoneError(f"{label}: 第 {lineno} 行字段重复: {word}")
            seen.add(word)
            try:
                rdclass = dns.rdataclass.from_text(up)
                idx += 1
                continue
            except dns.rdataclass.UnknownRdataclass:
                pass
            try:
                ttl = dns.ttl.from_text(word)
                idx += 1
                continue
            except dns.ttl.BadTTL:
                raise ZoneError(
                    f"{label}: 第 {lineno} 行无法识别的字段: {word}"
                    "（应为 TTL / IN / 类型）"
                ) from None

        if rdtype is None:
            raise ZoneError(f"{label}: 第 {lineno} 行缺少记录类型")
        if rdclass != dns.rdataclass.IN:
            raise ZoneError(f"{label}: 第 {lineno} 行仅支持 IN 类别")
        if rdtype not in ALLOWED_RDTYPES:
            raise ZoneError(
                f"{label}: 第 {lineno} 行不支持的记录类型 "
                f"{dns.rdatatype.to_text(rdtype)}；"
                f"允许 SOA/NS/A/AAAA/CNAME/DNAME"
            )

        if origin is None and rdtype == dns.rdatatype.SOA:
            raise ZoneError(f"{label}: 第 {lineno} 行 SOA 前需要 $ORIGIN")

        eff_ttl = ttl if ttl is not None else default_ttl
        if eff_ttl is None:
            raise ZoneError(
                f"{label}: 第 {lineno} 行没有 TTL，且未用 $TTL 设置缺省值"
            )

        # --- rdata：type 之后的全部 token（括号仅为续行符，需剔除）---
        rdata_words = [
            t.value for t in toks[idx:]
            if t.value not in ("(", ")")
        ]
        rdata_text = " ".join(rdata_words).strip()
        if not rdata_text:
            raise ZoneError(f"{label}: 第 {lineno} 行缺少 RDATA")
        try:
            rdata = dns.rdata.from_text(
                rdclass, rdtype, rdata_text,
                origin=origin, relativize=False,
            )
        except dns.exception.SyntaxError as exc:
            raise ZoneError(
                f"{label}: 第 {lineno} 行 RDATA 非法（{exc}）"
            ) from None
        except Exception as exc:
            raise ZoneError(
                f"{label}: 第 {lineno} 行 RDATA 无法解析"
                f"（{type(exc).__name__}: {exc}）"
            ) from None

        raw_records.append((owner, rdtype, eff_ttl, rdata, lineno))

    if origin is None:
        raise ZoneError(f"{label}: 缺少 $ORIGIN，且没有任何记录可推导起点")

    if origin_text is not None and initial_origin is not None \
            and initial_origin != origin:
        raise ZoneError(
            f"{label}: 提供的 origin {initial_origin} 与文本 $ORIGIN {origin} 不一致"
        )

    pz = _build(origin, raw_records, label)
    return pz


def _read_name_token(first, origin, label, lineno) -> dns.name.Name:
    word = first.value
    if word == "@":
        if origin is None:
            raise ZoneError(f"{label}: 第 {lineno} 行在 $ORIGIN 前使用 @")
        return origin
    try:
        return dns.name.from_text(word, origin=origin)
    except Exception as exc:
        raise ZoneError(f"{label}: 第 {lineno} 行属主名非法: {word} ({exc})")


_FIELD_TYPE_NAMES = {"SOA", "NS", "A", "AAAA", "CNAME", "DNAME"}


def _is_type(word: str) -> bool:
    # 仅把本服务支持的类型识别为“类型字段”；像 ns/hm 这类恰好等于某些
    # 冷门类型助记符的 RDATA 词不应在字段扫描阶段被误判。
    return word in _FIELD_TYPE_NAMES


# ---------------------------------------------------------------------------
# 组装与语义校验
# ---------------------------------------------------------------------------

def _build(origin, raw_records, label: str) -> ParsedZone:
    def rel(name: dns.name.Name) -> str:
        try:
            t = name.relativize(origin).to_text()
            return t or "@"
        except Exception:
            return name.to_text()

    # 1) 属主越区。
    for owner, rdtype, ttl, rdata, lineno in raw_records:
        if not owner.is_subdomain(origin):
            raise ZoneError(
                f"{label}: 第 {lineno} 行属主 {owner} 越出区域 {origin}"
            )
        rl = owner.relativize(origin).labels
        stars = [i for i, lb in enumerate(rl) if lb == b"*"]
        if stars and stars != [0]:
            raise ZoneError(
                f"{label}: 第 {lineno} 行通配符 * 只能作为最左标签（{rel(owner)}）"
            )
    records = [RR(o, t, ttl, rd) for (o, t, ttl, rd, _ln) in raw_records]

    pz = ParsedZone(origin=origin, records=records)
    for rr in records:
        pz.rrsets.setdefault(rr.owner, {}).setdefault(rr.rdtype, []).append(rr)
        if rr.rdtype == dns.rdatatype.SOA:
            if pz.soa is not None:
                raise ZoneError(f"{label}: 区域内出现多个 SOA 记录")
            pz.soa = rr

    if pz.soa is None:
        raise ZoneError(f"{label}: 区域缺少 SOA 记录，无法构成区域")
    if pz.soa.owner != origin:
        raise ZoneError(
            f"{label}: SOA 属主 {rel(pz.soa.owner)} 必须是区域起点 @（{origin}）"
        )

    # 2) 顶点约束。
    if dns.rdatatype.DNAME in pz.rdatasets(origin):
        raise ZoneError(f"{label}: DNAME 不能位于区域顶点 @（RFC 6672）")
    if dns.rdatatype.CNAME in pz.rdatasets(origin):
        raise ZoneError(f"{label}: CNAME 不能与 SOA/NS 共存于区域顶点 @")

    # 3) 别名互斥与重复目标。
    for owner, types in pz.rrsets.items():
        if dns.rdatatype.CNAME in types and len(types) > 1:
            raise ZoneError(
                f"{label}: CNAME 属主 {rel(owner)} 不能同时拥有其他记录类型"
            )
        if len({r.rdata.target for r in types.get(dns.rdatatype.CNAME, [])}) > 1:
            raise ZoneError(f"{label}: {rel(owner)} 上存在多个不同的 CNAME 目标")
        if dns.rdatatype.DNAME in types and dns.rdatatype.NS in types:
            raise ZoneError(
                f"{label}: DNAME 与 NS 不能共存于同一属主 {rel(owner)}"
            )
        if len({r.rdata.target for r in types.get(dns.rdatatype.DNAME, [])}) > 1:
            raise ZoneError(f"{label}: {rel(owner)} 上存在多个不同的 DNAME 目标")

    def assert_in_zone(target, where, kind, lineno):
        if not target.is_subdomain(origin):
            raise ZoneError(
                f"{label}: 第 {lineno} 行外部引用——{rel(where)} 的 {kind} 目标 "
                f"{target} 不在区域 {origin} 内（服务离线，不联网解析）"
            )

    # 4) 外部引用检查。
    for owner, rdtype, ttl, rdata, lineno in raw_records:
        if rdtype in (dns.rdatatype.NS, dns.rdatatype.CNAME,
                      dns.rdatatype.DNAME):
            assert_in_zone(rdata.target, owner,
                           dns.rdatatype.to_text(rdtype), lineno)

    # 5) 委派点结构。
    apex_ns_targets = {
        r.rdata.target
        for r in pz.rrsets[origin].get(dns.rdatatype.NS, [])
    }
    cuts = sorted(
        (o for o, ts in pz.rrsets.items()
         if o != origin and dns.rdatatype.NS in ts),
        key=lambda n: (len(n.labels), n),
    )
    for cut in cuts:
        types = pz.rrsets[cut]
        for rdtype in types:
            if rdtype not in (dns.rdatatype.NS, dns.rdatatype.A,
                              dns.rdatatype.AAAA):
                raise ZoneError(
                    f"{label}: 委派点 {rel(cut)} 下不得放置 "
                    f"{RDTYPE_NAMES.get(rdtype, rdtype)} 记录（切点只允许 NS/glue）"
                )
        ns_targets = {r.rdata.target for r in types[dns.rdatatype.NS]}
        for rt in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if rt in types and cut not in ns_targets:
                raise ZoneError(
                    f"{label}: 委派点 {rel(cut)} 上的 "
                    f"{dns.rdatatype.to_text(rt)} 记录不是其 NS 目标的 glue"
                )
        glue_owners = ns_targets | apex_ns_targets
        for owner, sub_types in pz.rrsets.items():
            if owner == cut or not owner.is_subdomain(cut):
                continue
            if owner not in glue_owners:
                raise ZoneError(
                    f"{label}: 委派子树 {rel(cut)} 之下出现非 glue 数据 "
                    f"{rel(owner)}（切点之下仅允许 NS 目标的地址 glue）"
                )
            for rdtype in sub_types:
                if rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    raise ZoneError(
                        f"{label}: glue 属主 {rel(owner)} 只能有 A/AAAA 记录"
                    )

    # 6) 结构点集合（存在性用于最近包围名 / 通配源判定）：
    #    * nonterminals —— 每个普通属主在区域内、自身无 RRset 的严格祖先
    #      （真实空非终结点；查询其名应得 NODATA）；
    #    * wildcard_parents —— 每个通配属主 *.p 的父节点 p。按 RFC 4592
    #      A.1.1，p 使 x.p 的最近包围名落在 p，从而 *.p 能命中 x.p；但 p
    #      自身若无普通数据/普通后代，查询 p 仍是 NXDOMAIN，故不并入
    #      nonterminals（普通通配的合成本不要求 p 真实存在）。
    for owner in pz.rrsets:
        if _owner_is_wildcard(owner):
            parent = owner.parent()
            if parent not in pz.rrsets:
                pz.wildcard_parents.add(parent)
            continue
        cur = owner
        while cur != origin:
            cur = cur.parent()
            if cur not in pz.rrsets:
                pz.nonterminals.add(cur)

    return pz
