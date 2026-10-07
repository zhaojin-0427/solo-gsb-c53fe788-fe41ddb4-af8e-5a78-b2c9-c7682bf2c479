"""解析器与影响分析的回归测试。

运行：``python -m pytest -q``（需 pytest）。
也可直接执行：``python tests/test_engine.py``。
"""
import random

import dns.name
import dns.rdatatype
import pytest

from app.zone import parse_zone, ZoneError
from app.resolver import Resolver
from app.diff import (
    analyze, answer_signature, rel_labels, abs_name, Cone, build_markers,
    MAX_PREIMAGE_DEPTH,
)
from app.resolver import MAX_ALIAS_HOPS

ORIGIN = "ex."


def zone(text):
    return parse_zone(text, ORIGIN, label="z")


def res(pz):
    return Resolver(pz)


def ask(r, name, qtype):
    qn = dns.name.from_text(name, origin=r.origin)
    return r.resolve(qn, dns.rdatatype.from_text(qtype))


# ---------------------------------------------------------------- 解析校验

def test_reject_unsupported_type():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "mail MX 10 mail\n"
    )
    try:
        zone(text)
        assert False, "应拒绝 MX"
    except ZoneError:
        pass


def test_reject_out_of_zone_owner():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "host.other. A 1.1.1.2\n"
    )
    try:
        zone(text)
        assert False, "应拒绝越区属主"
    except ZoneError:
        pass


def test_reject_external_reference():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "www CNAME target.external.\n"
    )
    try:
        zone(text)
        assert False, "应拒绝外部 CNAME 引用"
    except ZoneError:
        pass


def test_reject_cname_with_other_data():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "www CNAME host\nwww A 1.1.1.2\nhost A 1.1.1.3\n"
    )
    try:
        zone(text)
        assert False, "应拒绝 CNAME 与其他类型共存"
    except ZoneError:
        pass


def test_reject_delegation_with_data_below():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "sub NS ns.sub\nns.sub A 2.2.2.2\nstray.sub A 3.3.3.3\n"
    )
    try:
        zone(text)
        assert False, "切点之下除 glue 外不允许数据"
    except ZoneError:
        pass


def test_reject_apex_dname():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "@ DNAME target\n"
    )
    try:
        zone(text)
        assert False, "顶点 DNAME 非法"
    except ZoneError:
        pass


# ---------------------------------------------------------------- 解析行为

BASE = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 1 7200 3600 1209600 60
  NS ns
  NS ns2
ns A 192.0.2.1
ns2 AAAA 2001:db8::2
www CNAME host
host A 192.0.2.10
host AAAA 2001:db8::10
*.wild A 192.0.2.77
ent A 192.0.2.20
deep.ent A 192.0.2.21
d DNAME dt
dt A 192.0.2.90
sub NS ns.sub
ns.sub A 192.0.2.53
lo CNAME lo2
lo2 CNAME lo
"""


def test_exact_and_cname_chain():
    r = res(zone(BASE))
    a = ask(r, "host", "A")
    assert a.termination == "exact" and a.rcode == "NOERROR"
    a = ask(r, "www", "A")
    assert a.termination == "exact"
    kinds = [h.kind for h in a.hops]
    assert kinds == ["CNAME"]
    assert a.answer[0].rdata.target == dns.name.from_text("host.ex.")


def test_nodata_vs_ent_vs_nxdomain():
    r = res(zone(BASE))
    assert ask(r, "host", "NS").termination == "noerror_nodata"
    # ent 在 BASE 里自身有 A 记录（是叶子），其下级 x.ent 不存在 → NXDOMAIN。
    assert ask(r, "x.ent", "A").termination == "nxdomain"
    assert ask(r, "nothing", "A").termination == "nxdomain"
    # 真实空非终结点：自身无 RRset、仅因后代 deep.node.ent 而存在；
    # 查询其名得 NODATA，查询其不存在的下级仍得 NXDOMAIN。
    ent_zone = zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "deep.node.ent A 192.0.2.22\n"
    )
    er = res(ent_zone)
    assert ask(er, "node.ent", "A").termination == "ent_nodata"
    assert ask(er, "node.ent", "NS").termination == "ent_nodata"
    assert ask(er, "x.node.ent", "A").termination == "nxdomain"
    assert ask(er, "a.b.node.ent", "A").termination == "nxdomain"
    # 新增叶子名不会让其下级变成“存在”：x.leaf 仍 NXDOMAIN。
    leaf_zone = zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "leaf A 192.0.2.33\n"
    )
    lr = res(leaf_zone)
    assert ask(lr, "leaf", "A").termination == "exact"
    assert ask(lr, "x.leaf", "A").termination == "nxdomain"
    assert ask(lr, "a.x.leaf", "A").termination == "nxdomain"


def test_wildcard_parent_existence():
    # 只配置 *.p 时：x.p 命中通配；p 自身按 RFC 4592 A.1.1 仍为 NXDOMAIN
    # （通配父节点不是空非终结点）；p 再下一层不扩展。
    r = res(zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "*.p A 192.0.2.44\n"
    ))
    assert ask(r, "x.p", "A").termination == "wildcard_expansion"
    assert ask(r, "p", "A").termination == "nxdomain"
    assert ask(r, "a.x.p", "A").termination == "nxdomain"


def test_wildcard_expansion_and_deep_nonmatch():
    r = res(zone(BASE))
    a = ask(r, "x.wild", "A")
    assert a.termination == "wildcard_expansion"
    assert a.wildcard_source == dns.name.from_text("*.wild.ex.")
    assert a.answer[0].rdata.address == "192.0.2.77"
    # 多一层且中间无真实名称：通配不扩展（RFC 4592 closest encloser）。
    assert ask(r, "a.b.wild", "A").termination == "nxdomain"


def test_dname_rewrite_and_synthesis():
    r = res(zone(BASE))
    a = ask(r, "x.d", "A")
    # x.d 经 DNAME 合成 CNAME 指向 x.dt；x.dt 自身无记录，其最近包围名为
    # dt（dt 有 A 记录、是叶子），故 x.dt 不存在 → 链末端 NXDOMAIN，
    # 但应答里仍含合成 CNAME（在前）与真实 DNAME（在后）。
    assert a.hops[0].kind == "DNAME"
    assert a.answer[0].rdtype == dns.rdatatype.CNAME
    assert a.answer[1].rdtype == dns.rdatatype.DNAME
    assert a.answer[0].rdata.target == dns.name.from_text("x.dt.ex.")
    assert a.termination == "nxdomain"
    # 精确名 d 不触发 DNAME 合成。
    assert ask(r, "d", "A").termination == "noerror_nodata"
    # 目标子树存在记录时，沿 DNAME 链一路命中。
    b2 = zone(BASE + "x.dt A 192.0.2.95\n")
    a2 = Resolver(b2).resolve(
        dns.name.from_text("x.d.ex."), dns.rdatatype.A)
    assert a2.termination == "exact"
    assert any(
        x.rdtype == dns.rdatatype.A and x.rdata.address == "192.0.2.95"
        for x in a2.answer
    )


def test_delegation_referral():
    r = res(zone(BASE))
    for n in ("sub", "x.sub", "ns.sub"):
        a = ask(r, n, "A")
        assert a.termination == "delegation"
        assert a.aa is False
        assert a.authority[0].rdtype == dns.rdatatype.NS
    # glue 在 additional
    a = ask(r, "sub", "A")
    assert any(x.rdtype == dns.rdatatype.A and
               x.rdata.address == "192.0.2.53" for x in a.additional)


def test_alias_loop_is_marked_not_errored():
    r = res(zone(BASE))
    a = ask(r, "lo", "A")
    assert a.termination == "alias_loop"
    assert a.rcode == "NOERROR"
    assert len(a.answer) >= 2


# ---------------------------------------------------------------- 影响模式

def _suffix(child, parent):
    return child == parent or (
        len(child) > len(parent)
        and child[len(child) - len(parent):] == parent
    )


def _depth(child, parent):
    return len(child) - len(parent) if _suffix(child, parent) else -1


def _name_in(labels, cone: Cone):
    P, Q = labels, cone.labels
    if cone.kind == "exact":
        return P == Q
    if cone.kind == "star":
        return _depth(P, Q) == 1
    return _depth(P, Q) >= 0


def _in_pattern(labels, p):
    return _name_in(labels, p.scope) and not any(
        _name_in(labels, e) for e in p.exclude
    )


def assert_sound(b, c, qtype, vocab, rounds=3000):
    rb, rc = res(b), res(c)
    qt = dns.rdatatype.from_text(qtype)
    patterns = analyze(b, c, [qt])[0].patterns
    random.seed(7)
    for _ in range(rounds):
        labs = tuple(random.choice(vocab)
                     for _ in range(random.randint(0, 40)))
        # dnspython 限定全名不超过 255 字节；跳过构造出的超长名。
        if sum(len(lb) + 1 for lb in labs) > 250:
            continue
        qn = abs_name(labs, b.origin)
        changed = answer_signature(rb.resolve(qn, qt)) != answer_signature(
            rc.resolve(qn, qt))
        members = [i for i, p in enumerate(patterns)
                   if _in_pattern(labs, p)]
        if changed:
            assert len(members) == 1, (qtype, labs, members)
        else:
            assert members == [], (qtype, labs, members)
    for p in patterns:
        assert _in_pattern(rel_labels(p.witness, b.origin), p)


CHANGE_B = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 1 1 1 1 1
  NS ns
ns A 192.0.2.1
www A 192.0.2.10
api A 192.0.2.20
old CNAME www
sub A 10.0.0.1
child.sub A 10.0.0.2
dlg NS ns.dlg
ns.dlg A 192.0.2.53
*.wild A 192.0.2.77
d DNAME dt
dt A 192.0.2.90
"""

CHANGE_C = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 2 1 1 1 1
  NS ns
ns A 192.0.2.1
www A 192.0.2.11
api AAAA 2001:db8::20
new A 192.0.2.30
old CNAME www
sub A 10.0.0.1
child.sub A 10.0.0.2
dlg NS ns.dlg
ns.dlg A 192.0.2.53
*.wild A 192.0.2.78
d DNAME dt
dt A 192.0.2.91
leaf.dt A 192.0.2.92
"""

VOCAB = ["www", "api", "new", "old", "sub", "child", "wild", "d", "dt",
         "leaf", "ns", "dlg", "x", "y", "z", "*", "w-0", "ww-0",
         "w-5", "w-9", "foo", "bar"]


def test_patterns_sound_all_types():
    b, c = parse_zone(CHANGE_B, ORIGIN, label="b"), parse_zone(
        CHANGE_C, ORIGIN, label="c")
    for t in ("A", "AAAA", "NS", "CNAME", "DNAME", "SOA"):
        assert_sound(b, c, t, VOCAB)


def test_known_a_changes():
    b, c = parse_zone(CHANGE_B, ORIGIN, label="b"), parse_zone(
        CHANGE_C, ORIGIN, label="c")
    scopes = {p.scope.render()
              for p in analyze(b, c, [dns.rdatatype.A])[0].patterns}
    assert "www" in scopes
    assert "api" in scopes          # A 删除 → NODATA
    assert "new" in scopes          # 新增
    assert "*.wild" in scopes       # 通配地址变更
    assert "dt" in scopes           # DNAME 目标 A 变更
    assert "leaf.d" in scopes       # DNAME 拉回覆盖未列名


def test_new_leaf_does_not_fabricate_descendant_patterns():
    # 新增叶子 new：只允许精确模式 new；不得误报 *.new / **.new。
    hdr = ("$ORIGIN ex.\n$TTL 60\n@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
           "ns A 192.0.2.1\n")
    b = parse_zone(hdr.format(sn=1), ORIGIN, label="b")
    c = parse_zone(hdr.format(sn=2) + "new A 192.0.2.30\n",
                   ORIGIN, label="c")
    ps = analyze(b, c, [dns.rdatatype.A])[0].patterns
    scopes = {p.scope.render() for p in ps}
    assert scopes == {"new"}
    # 其下级在两版里都不存在。
    rb, rc = Resolver(b), Resolver(c)
    for n in ("x.new", "a.x.new", "*.new"):
        qn = dns.name.from_text(n, origin=b.origin)
        a = rb.resolve(qn, dns.rdatatype.A)
        z = rc.resolve(qn, dns.rdatatype.A)
        assert a.termination == z.termination == "nxdomain", n


def test_ent_patterns_cover_only_changed_names():
    # 新增深层叶子 deep.node.ent：精确名 + 两级新 ENT，不多不少。
    hdr = ("$ORIGIN ex.\n$TTL 60\n@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
           "ns A 192.0.2.1\n")
    b = parse_zone(hdr.format(sn=1), ORIGIN, label="b")
    c = parse_zone(hdr.format(sn=2) + "deep.node.ent A 192.0.2.51\n",
                   ORIGIN, label="c")
    ps = analyze(b, c, [dns.rdatatype.A])[0].patterns
    got = {p.scope.render(): (p.baseline.termination, p.candidate.termination)
           for p in ps}
    assert got == {
        "deep.node.ent": ("nxdomain", "exact"),
        "node.ent": ("nxdomain", "ent_nodata"),
        "ent": ("nxdomain", "ent_nodata"),
    }
    rc = Resolver(c)
    # ENT 的未列下级仍不存在。
    for n in ("x.node.ent", "x.ent", "a.b.node.ent"):
        a = rc.resolve(dns.name.from_text(n, origin=c.origin),
                       dns.rdatatype.A)
        assert a.termination == "nxdomain", n


def test_nearer_node_blocks_upper_wildcard_in_diff():
    # *.e 存在，候选新增精确叶子 leaf.e：leaf.e 变化，但其下级被阻断、
    # 顶点其它未列名仍走通配，模式必须互斥完备。
    hdr = ("$ORIGIN ex.\n$TTL 60\n@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
           "ns A 192.0.2.1\n*.e A 192.0.2.40\n")
    b = parse_zone(hdr.format(sn=1), ORIGIN, label="b")
    c = parse_zone(hdr.format(sn=2) + "leaf.e A 192.0.2.41\n",
                   ORIGIN, label="c")
    ps = analyze(b, c, [dns.rdatatype.A])[0].patterns
    scopes = {p.scope.render() for p in ps}
    assert "leaf.e" in scopes
    assert "e" in scopes               # 通配父升格为真实 ENT
    rb, rc = Resolver(b), Resolver(c)
    qt = dns.rdatatype.A
    # 阻断：x.leaf.e 两版都是 NXDOMAIN，不属于任何模式。
    qn = dns.name.from_text("x.leaf.e", origin=b.origin)
    assert rb.resolve(qn, qt).termination == "nxdomain"
    assert rc.resolve(qn, qt).termination == "nxdomain"
    # 未受影响的通配名仍命中 *.e（未变化）。
    qn2 = dns.name.from_text("other.e", origin=b.origin)
    assert rc.resolve(qn2, qt).wildcard_source == dns.name.from_text(
        "*.e.ex.")
    assert_sound(b, c, "A", ["e", "leaf", "other", "x", "y", "ns"])


def test_dname_target_deep_unlisted_covered():
    b = parse_zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "d DNAME dt\ndt A 5.5.5.5\n", ORIGIN, label="b")
    c = parse_zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 2 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "d DNAME dt\ndt A 5.5.5.5\na.b.dt A 9.9.9.9\n", ORIGIN, label="c")
    scopes = {p.scope.render()
              for p in analyze(b, c, [dns.rdatatype.A])[0].patterns}
    assert "a.b.d" in scopes and "a.b.dt" in scopes


def test_identical_zones_no_patterns():
    b = parse_zone(CHANGE_B, ORIGIN, label="b")
    c = parse_zone(CHANGE_B, ORIGIN, label="c")
    for t in ("A", "NS"):
        assert analyze(b, c, [dns.rdatatype.from_text(t)])[0].patterns == []


# ------------------------------------------------ DNAME 自引用与跳数有限化

SELF_DNAME_HDR = (
    "$ORIGIN ex.\n$TTL 60\n"
    "@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
    "ns A 192.0.2.1\n"
    "x.d DNAME d\n"
)


def _self_dname_pair(a1="192.0.2.10", a2="192.0.2.20"):
    b = parse_zone(
        SELF_DNAME_HDR.format(sn=1) + f"a.d A {a1}\n", ORIGIN, label="b")
    c = parse_zone(
        SELF_DNAME_HDR.format(sn=2) + f"a.d A {a2}\n", ORIGIN, label="c")
    return b, c


def test_self_referential_dname_markers_are_finite():
    # 回归：旧实现的拉回不动点在 ``x.d DNAME d`` 上无限生成 x.x.d……，
    # build_markers / analyze 永不返回（POST /impact 无响应）。
    b, c = _self_dname_pair()
    markers, _fresh = build_markers(b, c)
    assert markers == set(markers)  # 能正常返回即通过
    # 反向拉回深度有限：经一次拉回的 x.d 等存在，但不会无限增长。
    assert ("d",) in markers and ("x", "d") in markers
    assert ("x",) * (MAX_ALIAS_HOPS + 5) + ("d",) not in markers
    td = analyze(b, c, [dns.rdatatype.A])[0]
    assert td.patterns                      # 必须在有限时间内产出结果


def test_self_dname_hop_boundary_patterns():
    # 与 /resolve 一致：a.x^k.d 经 k 跳 DNAME 改写后命中 a.d。
    # k <= 31 时末端 a.d 的 A 变化可见；k == 32 触别名跳数上限，不可见。
    b, c = _self_dname_pair()
    rb, rc = Resolver(b), Resolver(c)
    qt = dns.rdatatype.A
    patterns = analyze(b, c, [qt])[0].patterns
    scopes = {p.scope.render() for p in patterns}

    expect = {"a.d"} | {f"a.{'x.' * k}d" for k in range(1, MAX_ALIAS_HOPS)}
    assert scopes == expect
    assert len(patterns) == MAX_ALIAS_HOPS
    # 每个模式的见证应答与解析器直接解析完全一致。
    for p in patterns:
        qn = p.witness
        a1, a2 = rb.resolve(qn, qt), rc.resolve(qn, qt)
        assert answer_signature(p.baseline) == answer_signature(a1)
        assert answer_signature(p.candidate) == answer_signature(a2)

    # 31 层 x：31 跳，仍取到变化后的 A；32 层 x：32 跳触顶，两版相同。
    n31 = dns.name.from_text("a." + "x." * 31 + "d", origin=b.origin)
    n32 = dns.name.from_text("a." + "x." * 32 + "d", origin=b.origin)
    a31b, a31c = rb.resolve(n31, qt), rc.resolve(n31, qt)
    a32b, a32c = rb.resolve(n32, qt), rc.resolve(n32, qt)
    assert len(a31b.hops) == 31 and a31b.termination == "exact"
    assert answer_signature(a31b) != answer_signature(a31c)
    assert len(a32b.hops) == MAX_ALIAS_HOPS
    assert a32b.termination == a32c.termination == "alias_chain_limit"
    assert answer_signature(a32b) == answer_signature(a32c)


def test_self_dname_patterns_sound_with_deep_names():
    b, c = _self_dname_pair()
    assert_sound(
        b, c, "A",
        ["a", "d", "x", "y", "z", "foo", "ns", "w-0", "ww-0", "*"],
        rounds=4000,
    )


def test_self_dname_only_present_in_candidate_is_finite_and_sound():
    # 自引用 DNAME 只在候选版出现：基线 NXDOMAIN 与候选别名链/命中之间的
    # 变化同样须有限、互斥且完备。
    hdr = ("$ORIGIN ex.\n$TTL 60\n@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
           "ns A 192.0.2.1\n")
    b = parse_zone(
        hdr.format(sn=1) + "t A 10.0.0.9\na.t A 10.0.0.10\n",
        ORIGIN, label="b")
    c = parse_zone(
        hdr.format(sn=2)
        + "t A 10.0.0.9\na.t A 10.0.0.11\nx.t DNAME t\n",
        ORIGIN, label="c")
    markers, _ = build_markers(b, c)
    # 标记深度受反向跳数限制（再深一层的 a.x^32.t 仅可能由前缀闭合得到，
    # 其自身是结构点；不会出现 a.x^33.t 之类无限拉回产物）。
    assert ("a",) + ("x",) * (MAX_PREIMAGE_DEPTH + 2) + ("t",) not in markers
    assert_sound(
        b, c, "A",
        ["a", "t", "x", "y", "ns", "foo", "w-0", "ww-0"],
        rounds=4000,
    )


# --------------------------------------- 63 字节长标签 DNAME：线长有限化

LONG = "x" * 63

LONG_DNAME_HDR = (
    "$ORIGIN ex.\n$TTL 60\n"
    "@ SOA ns hm {sn} 1 1 1 1\n NS ns\n"
    "ns A 192.0.2.1\n"
    f"{LONG}.d DNAME d\n"
)


def _long_dname_pair(a1="192.0.2.10", a2="192.0.2.20"):
    b = parse_zone(
        LONG_DNAME_HDR.format(sn=1) + f"a.d A {a1}\n", ORIGIN, label="b")
    c = parse_zone(
        LONG_DNAME_HDR.format(sn=2) + f"a.d A {a2}\n", ORIGIN, label="c")
    return b, c


def test_long_label_self_dname_markers_wire_bounded():
    # 回归：L=63 个 x 时，旧闭包按 31 跳拉回会造出 2050 字节的名字，
    # build_cells 拼接 w-N 探针时 dns.name 抛 NameTooLong，POST /impact
    # 直接 500。修复后反向标记与全部探针都必须是 ≤255 字节的合法名。
    from app.diff import _abs_wire
    b, c = _long_dname_pair()
    markers, pool = build_markers(b, c)
    assert all(_abs_wire(m, b.origin) <= 255 for m in markers)
    from app.diff import build_cells
    cells = build_cells(markers, pool, b.origin)
    assert all(_abs_wire(cl.probe, b.origin) <= 255 for cl in cells)

    # 自引用规则每跳加 64 线字节：a.L^k.d 合法的只有 k=0..3
    # （origin ex. 占 4 字节：8/72/136/200），k=4 达 264 字节，无法查询。
    for k in range(4):
        assert ("a",) + (LONG,) * k + ("d",) in markers
    assert ("a",) + (LONG,) * 4 + ("d",) not in markers
    assert (LONG,) * 4 + ("d",) not in markers

    # 32 跳跳数上限仍在（只是本场景先被线长截断）。
    assert ("x",) * (MAX_ALIAS_HOPS + 5) + ("d",) not in markers

    with pytest.raises(dns.name.NameTooLong):
        dns.name.from_text("a." + (LONG + ".") * 4 + "d", origin=b.origin)


def test_long_label_self_dname_patterns_and_resolve_parity():
    # /impact 与 /resolve 互斥完备：恰为 k=0..3 四个精确模式，见证合法，
    # 逐字段与解析器一致；k=4 无法查询，不产生见证。
    b, c = _long_dname_pair()
    rb, rc = Resolver(b), Resolver(c)
    qt = dns.rdatatype.A
    patterns = analyze(b, c, [qt])[0].patterns
    expect = {"a." + (LONG + ".") * k + "d" for k in range(4)}
    assert {p.scope.render() for p in patterns} == expect
    assert len(patterns) == 4
    for p in patterns:
        assert len(p.witness.to_wire()) <= 255
        assert answer_signature(p.baseline) == answer_signature(
            rb.resolve(p.witness, qt))
        assert answer_signature(p.candidate) == answer_signature(
            rc.resolve(p.witness, qt))
    # 末端 A 可见且不同；跳数等于长标签层数。
    by_hops = {len(p.baseline.hops): p for p in patterns}
    assert set(by_hops) == {0, 1, 2, 3}
    assert by_hops[3].candidate.termination == "exact"
    assert by_hops[3].candidate.answer[-1].rdata.address == "192.0.2.20"


def test_long_label_self_dname_patterns_sound():
    b, c = _long_dname_pair()
    assert_sound(
        b, c, "A",
        ["a", "d", LONG, "ns", "hm", "y", "z", "foo",
         "*", "0", "1", "w-0", "ww-0", "00"],
        rounds=4000,
    )


def test_tight_headroom_star_uses_short_fresh_label():
    # 标记节点 N 占 253 线字节（origin example. 占 9）：余 2 字节，放得下
    # 一字符短标签（探针 255），却放不下 4 字节的 w-0；deep 探针要两个
    # 标签（≥4 字节）更放不下——此时须取短新鲜标签作见证，不截断名字，
    # deep 等价类（两层下级）在合法名称空间为空，不建单元。
    from app.diff import build_cells, _abs_wire
    X = "x" * 63
    T = "t" * 51
    n_name = f"{T}.{X}.{X}.{X}"
    star_name = f"*.{n_name}"
    # *.N 恰好 255 字节，可配置；候选版新增该通配后一标签空隙发生变化。
    assert len(dns.name.from_text(star_name,
           origin=dns.name.from_text("example.")).to_wire()) == 255
    hdr = ("$ORIGIN example.\n$TTL 60\n"
           "@ SOA ns hm {sn} 1 1 1 1\n NS ns\nns A 192.0.2.1\n")
    b = parse_zone(hdr.format(sn=1) + f"{n_name} A 192.0.2.9\n",
                   "example.", label="b")
    c = parse_zone(
        hdr.format(sn=2) + f"{n_name} A 192.0.2.9\n{star_name} A 192.0.2.10\n",
        "example.", label="c")
    markers, pool = build_markers(b, c)
    n_rel = rel_labels(dns.name.from_text(n_name, origin=b.origin), b.origin)
    assert _abs_wire(n_rel, b.origin) == 253
    cells = build_cells(markers, pool, b.origin)
    star_cells = [cl for cl in cells if cl.kind == "star"
                  and cl.labels == n_rel]
    deep_cells = [cl for cl in cells if cl.kind == "deep"
                  and cl.labels == n_rel]
    assert len(star_cells) == 1 and deep_cells == []
    probe_label = star_cells[0].probe[0]
    assert len(probe_label) == 1          # 一字符短新鲜标签
    assert probe_label not in {"x", "t", "*"}  # 不与真实标签冲突
    assert _abs_wire(star_cells[0].probe, b.origin) == 255

    qt = dns.rdatatype.A
    patterns = analyze(b, c, [qt])[0].patterns
    star_pat = next(p for p in patterns if p.scope.kind == "star"
                    and p.scope.labels == n_rel)
    assert len(star_pat.witness.to_wire()) == 255
    rb, rc = Resolver(b), Resolver(c)
    assert answer_signature(star_pat.baseline) == answer_signature(
        rb.resolve(star_pat.witness, qt))
    assert answer_signature(star_pat.candidate) == answer_signature(
        rc.resolve(star_pat.witness, qt))
    assert star_pat.candidate.termination == "wildcard_expansion"



# ---------------------------------------------------------------- HTTP 端到端

def test_http_impact_self_dname_scenario():
    # POST /impact 在自引用 DNAME 场景下必须正常返回（旧实现无响应）；
    # 见证应答与 POST /resolve 逐字段一致；31 层变化、32 层不报；
    # 非法区域仍整单 400。
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    body = {
        "origin": "example.",
        "types": ["A"],
        "baseline": (
            "$ORIGIN example.\n$TTL 3600\n"
            "@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\n"
            "ns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.10\n"
        ),
        "candidate": (
            "$ORIGIN example.\n$TTL 3600\n"
            "@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\n"
            "ns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.20\n"
        ),
    }
    r = client.post("/impact", json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["type_summary"] == [
        {"type": "A", "changed_cells": 32, "patterns": 32}]
    patterns = out["patterns"]
    assert len(patterns) == 32

    # 0 跳与 31 跳见证与 /resolve 逐字段一致。
    for k in (0, 31):
        name = "a." + "x." * k + "d"
        rr = client.post("/resolve", json={
            "origin": "example.", "name": name, "type": "A",
            "baseline": body["baseline"], "candidate": body["candidate"],
        })
        assert rr.status_code == 200
        ro = rr.json()
        assert ro["identical"] is False
        p = next(p for p in patterns if p["scope"]["selector"] == name)
        assert p["baseline"] == ro["baseline"]
        assert p["candidate"] == ro["candidate"]

    # 32 层：两版 alias_chain_limit、identical，且不在任何模式中。
    name32 = "a." + "x." * 32 + "d"
    rr = client.post("/resolve", json={
        "origin": "example.", "name": name32, "type": "A",
        "baseline": body["baseline"], "candidate": body["candidate"],
    })
    ro = rr.json()
    assert ro["identical"] is True
    assert ro["baseline"]["termination"] == "alias_chain_limit"
    assert ro["candidate"]["termination"] == "alias_chain_limit"
    assert len(ro["baseline"]["alias_chain"]) == MAX_ALIAS_HOPS
    assert all(p["scope"]["selector"] != name32 for p in patterns)

    # 非法区域（外部 CNAME 目标）整单 400。
    bad = dict(body, baseline=body["baseline"] + "www CNAME ext.out.\n")
    r = client.post("/impact", json=bad)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_zone"

    # 越区查询名 400。
    r = client.post("/resolve", json={
        "origin": "example.", "name": "a.d.other.", "type": "A",
        "baseline": body["baseline"], "candidate": body["candidate"],
    })
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "out_of_zone"


def test_http_impact_long_label_self_dname_scenario():
    # POST /impact 在 63 字节长标签自引用 DNAME 场景下必须正常返回
    # （旧实现因探针 NameTooLong 而 500）；模式与 /resolve 一致，恰为
    # 0..3 跳四个；第 4 跳名称超 255 字节不可查询、不作见证；非法区域
    # 仍整单 400。
    from fastapi.testclient import TestClient
    from app.main import app

    L = "x" * 63
    client = TestClient(app)
    body = {
        "origin": "example.",
        "types": ["A"],
        "baseline": (
            "$ORIGIN example.\n$TTL 3600\n"
            "@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\n"
            f"ns1 A 192.0.2.1\n{L}.d DNAME d\na.d A 192.0.2.10\n"
        ),
        "candidate": (
            "$ORIGIN example.\n$TTL 3600\n"
            "@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\n"
            f"ns1 A 192.0.2.1\n{L}.d DNAME d\na.d A 192.0.2.20\n"
        ),
    }
    r = client.post("/impact", json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["type_summary"] == [
        {"type": "A", "changed_cells": 4, "patterns": 4}]
    patterns = out["patterns"]
    assert {p["scope"]["selector"] for p in patterns} == {
        "a." + (L + ".") * k + "d" for k in range(4)
    }
    for p in patterns:
        assert len(dns.name.from_text(
            p["witness"]["name"], origin=dns.name.from_text("example.")
        ).to_wire()) <= 255

    # 每个见证都与 /resolve 逐字段一致。
    for p in patterns:
        name = p["scope"]["selector"]
        rr = client.post("/resolve", json={
            "origin": "example.", "name": name, "type": "A",
            "baseline": body["baseline"], "candidate": body["candidate"],
        })
        assert rr.status_code == 200
        ro = rr.json()
        assert ro["identical"] is False
        assert p["baseline"] == ro["baseline"]
        assert p["candidate"] == ro["candidate"]

    # 4 层长标签（269 字节）：查询名本身非法 → 400 invalid_name，
    # 且不产生任何模式（超长名不作见证）。
    name4 = "a." + (L + ".") * 4 + "d"
    rr = client.post("/resolve", json={
        "origin": "example.", "name": name4, "type": "A",
        "baseline": body["baseline"], "candidate": body["candidate"],
    })
    assert rr.status_code == 400
    assert rr.json()["error"]["code"] == "invalid_name"
    assert all(p["scope"]["selector"] != name4 for p in patterns)

    # 非法区域（外部 CNAME 目标）依旧整单 400。
    bad = dict(body, baseline=body["baseline"] + "www CNAME ext.out.\n")
    r = client.post("/impact", json=bad)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_zone"


if __name__ == "__main__":
    import inspect
    import sys
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
