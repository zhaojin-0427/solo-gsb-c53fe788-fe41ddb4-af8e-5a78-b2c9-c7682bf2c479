"""影响分析：把“域内所有名称 × 所列类型”切成有限等价类并比较两版应答。

名称集合（作用域）用三类锥表示（相对 ``$ORIGIN``）：

* ``exact(name)``：单个名称；
* ``star(prefix)``：``*.prefix`` —— prefix 的直接下级（恰好一个标签）；
* ``sub(prefix)``：``**.prefix`` —— prefix 本身及其任意多层下级
  （零或多个标签）。

无限名称空间通过“标记名 trie + 虚拟新鲜标签”有限化：

* 两版区域的全部真实属主、通配符父节点、空非终结点都作为标记；
* DNAME 目标子树的结构点通过拉回（preimage）闭包映射回源侧，
  因此 DNAME 目标变化影响到的未列名也会被覆盖；闭包**按实际跳数
  有限化**（深度上限 ``MAX_ALIAS_HOPS - 1``）：一次拉回对应正向解析的
  一跳 DNAME 改写，像 ``x.d DNAME d`` 这类自引用规则只生成有限个
  x.d / x.x.d / … 标记，不会无限增长，且边界与解析器一致——31 跳仍可
  见末端变化，32 跳触顶（alias_chain_limit）后两版应答相同；
* trie 上每个标记节点的直接下级空隙用 ``w-*``（一标签）与
  ``ww-*``（多层）两个虚拟标签代表。

输出模式形如 ``锥 − 排除子树列表``，同类型的模式互斥且并集覆盖全区域。
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.name
import dns.rdatatype

from .zone import ParsedZone
from .resolver import Resolver, Answer, MAX_ALIAS_HOPS

# 反向拉回（preimage）的最大深度：一次拉回对应正向解析里的一跳 DNAME
# 改写。解析器在第 MAX_ALIAS_HOPS 跳处以 alias_chain_limit 终止，末端
# 数据不再可见；因此只需把“经不超过 MAX_ALIAS_HOPS-1 跳改写即可到达
# 末端结构点”的源侧名称拉成显式标记。再深的名称两版都在跳数上限处
# 终止，其变化判定由既有探针空隙承载——这与 /resolve 的逐跳结果一致：
# 31 层 x 仍能看到目标变化，32 层触顶后两版应答相同。
MAX_PREIMAGE_DEPTH = MAX_ALIAS_HOPS - 1

# ---------------------------------------------------------------------------
# 锥与模式
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Cone:
    kind: str                 # exact / star / sub
    labels: tuple[str, ...]   # 相对 origin，文本序（最左在 0）；空=顶点

    def render(self) -> str:
        body = ".".join(self.labels)
        if self.kind == "exact":
            return body or "@"
        if self.kind == "star":
            return "*" if not body else f"*.{body}"
        return "**" if not body else f"**.{body}"

    @staticmethod
    def exact(labels: tuple[str, ...]) -> "Cone":
        return Cone("exact", tuple(labels))

    @staticmethod
    def star(labels: tuple[str, ...]) -> "Cone":
        return Cone("star", tuple(labels))

    @staticmethod
    def sub(labels: tuple[str, ...]) -> "Cone":
        return Cone("sub", tuple(labels))


@dataclass
class Pattern:
    scope: Cone
    exclude: list[Cone]
    witness: dns.name.Name
    witness_kind: str          # exact / star / deep
    baseline: Answer
    candidate: Answer


# ---------------------------------------------------------------------------
# 名称工具
# ---------------------------------------------------------------------------

def rel_labels(name: dns.name.Name, origin: dns.name.Name) -> tuple[str, ...]:
    return tuple(lb.decode() for lb in name.relativize(origin).labels)


def abs_name(labels: tuple[str, ...], origin: dns.name.Name) -> dns.name.Name:
    if not labels:
        return origin
    return dns.name.from_text(".".join(labels), origin=origin)


# ---------------------------------------------------------------------------
# 标记 trie
# ---------------------------------------------------------------------------

def _collect_owner_labels(pz: ParsedZone, origin: dns.name.Name) -> set[tuple[str, ...]]:
    out: set[tuple[str, ...]] = {()}
    for owner in pz.rrsets:
        rel = rel_labels(owner, origin)
        out.add(rel)
        # 通配属主 *.p：其路径前缀 p 也要入 trie，以便挂子锥。
        if rel and rel[0] == "*":
            out.add(rel[1:])
    return out


def _dname_rules(pz: ParsedZone, origin: dns.name.Name):
    for owner, types in pz.rrsets.items():
        if dns.rdatatype.DNAME in types:
            rr = types[dns.rdatatype.DNAME][0]
            yield rel_labels(owner, origin), rel_labels(rr.rdata.target, origin)


def build_markers(
    base: ParsedZone, cand: ParsedZone
) -> tuple[set[tuple[str, ...]], dict[tuple[str, ...], tuple[str, str]]]:
    """返回 (标记名集合, 每个 trie 节点对应的一对虚拟新鲜标签)。"""
    origin = base.origin
    markers = _collect_owner_labels(base, origin) | _collect_owner_labels(cand, origin)

    # DNAME 拉回闭包：两版区域里任一 DNAME 规则都要作用于当前全部标记，
    # 直到深度达到 MAX_PREIMAGE_DEPTH。这样无论变化在源侧还是目标侧，受
    # 影响的未列名都会落进某个显式单元，而不是只被深层虚拟探针笼统覆盖。
    #
    # 关键：闭包必须**按实际跳数有限化**。像 ``x.d DNAME d`` 这类自引用
    # 规则会把目标侧标记 d 拉成 x.d，再拉成 x.x.d……若无深度限制便无限
    # 生成（旧实现的不动点循环在此直接挂死）。每个标记记录其“经多少跳
    # DNAME 反向改写得到”的最短距离：属主/通配父节点为 0，每做一次拉回
    # 距离 +1；距离已达 MAX_PREIMAGE_DEPTH 的标记不再继续拉回——由它再
    # 拉回得到的名字正向解析时至少需要 MAX_ALIAS_HOPS 跳，必在跳数上限
    # 处终止，两版末端数据都不可见（与 /resolve 一致），其变化与否由其
    # 所属的 star/deep 探针空隙代表。
    rules = list(_dname_rules(base, origin)) + list(_dname_rules(cand, origin))

    # dist[m] = m 距最近 0 层标记的最短反向改写跳数。
    dist: dict[tuple[str, ...], int] = {m: 0 for m in markers}
    frontier = set(markers)
    for _depth in range(MAX_PREIMAGE_DEPTH):
        if not frontier:
            break
        new_frontier: set[tuple[str, ...]] = set()
        for src, tgt in rules:
            wildcard_dname = bool(src) and src[0] == "*"
            owner_parent = src[1:] if wildcard_dname else src
            for m in frontier:
                if m == tgt:
                    rel: tuple[str, ...] = ()
                elif len(m) > len(tgt) and m[-len(tgt):] == tgt:
                    rel = m[: len(m) - len(tgt)]
                else:
                    continue
                if wildcard_dname:
                    if not rel:
                        # 目标顶点 → 单层源名由 owner_parent 的 star 探针覆盖。
                        continue
                    # rel=(y,...) 对应源侧 (任意x, y, ...)+owner_parent；
                    # 加入剥离 x 后的结构点，使“x 之下”成为显式标记。
                    new = rel + owner_parent
                else:
                    new = rel + src
                if new not in dist:
                    dist[new] = _depth + 1
                    markers.add(new)
                    new_frontier.add(new)
        frontier = new_frontier

    # trie 前缀闭合。
    for m in list(markers):
        for i in range(1, len(m)):
            markers.add(m[i:])

    # 为每个 trie 节点分配一对互不冲突的虚拟标签。
    real_labels = {lb for m in markers for lb in m if lb != "*"}
    fresh_map: dict[tuple[str, ...], tuple[str, str]] = {}
    i = 0
    for node in sorted(markers, key=lambda x: (len(x), x)):
        while f"w-{i}" in real_labels or f"ww-{i}" in real_labels:
            i += 1
        w, ww = f"w-{i}", f"ww-{i}"
        real_labels.add(w)
        real_labels.add(ww)
        i += 1
        fresh_map[node] = (w, ww)

    return markers, fresh_map


# ---------------------------------------------------------------------------
# 单元（分区原子）
# ---------------------------------------------------------------------------

@dataclass
class Cell:
    kind: str               # exact / star / deep
    labels: tuple[str, ...] # 锥的标签（star/deep 为父节点）
    probe: tuple[str, ...]  # 实际解析的代表名


def build_cells(
    markers: set[tuple[str, ...]],
    fresh_map: dict[tuple[str, ...], tuple[str, str]],
) -> list[Cell]:
    cells: list[Cell] = []
    for node in sorted(markers, key=lambda x: (len(x), x)):
        # 字面通配属主（(*,P,...)）只建精确单元：名字 *.P 作为 P 的一标签
        # 下级，已落在 P 的 star 空隙等价类中（其应答也由该探针见证）；
        # 单独保留精确单元仅为区分“字面 * 名”与新鲜标签 w 的应答签名
        # （两者在权威侧可能不同）。它的 star/deep 空隙（w.*.P 等）是不可
        # 能的名字（通配符只能是最左标签），不建单元，否则会得到与父节点
        # star 单元同集合、同渲染（*.P）的重复锥而相互重叠。
        if node and node[0] == "*":
            cells.append(Cell("exact", node, node))
            continue
        w, ww = fresh_map[node]
        # 1) 精确单元。
        cells.append(Cell("exact", node, node))
        # 2) 一标签空隙：node 的直接下级中不属于任何标记子节点的名字
        #    （其中包含字面 * 属主；新鲜标签 w 与之同属一个等价类）。
        cells.append(Cell("star", node, (w,) + node))
        # 3) 多层空隙：ww 开头，下面再放一层 w，代表“进入未标记子树后”
        #    的任意深度名称。
        cells.append(Cell("deep", node, (ww, w) + node))
    return cells


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 应答签名（忽略 TTL；owner/rdata 全部按线上形态比较）
# ---------------------------------------------------------------------------

def _rr_key(rr):
    if rr.rdtype == dns.rdatatype.SOA:
        rd = rr.rdata
        return (
            "SOA", tuple(rr.owner.labels),
            tuple(rd.mname.labels), tuple(rd.rname.labels),
            rd.serial, rd.refresh, rd.retry, rd.expire, rd.minimum,
        )
    if rr.rdtype in (dns.rdatatype.NS, dns.rdatatype.CNAME,
                     dns.rdatatype.DNAME):
        return (rr.rdtype, tuple(rr.owner.labels), tuple(rr.rdata.target.labels))
    if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return (rr.rdtype, tuple(rr.owner.labels), rr.rdata.address)
    return (rr.rdtype, tuple(rr.owner.labels), rr.rdata.to_text())


def _authority_key(rr):
    # 否定应答 authority 里的 SOA 只比较“存在/属主/类型”；其内容变化
    # （如 serial 自增）由顶点 SOA 类型的比较单独承载，避免一次序列号
    # 变更把全部 NODATA/NXDOMAIN 都标成变化。
    if rr.rdtype == dns.rdatatype.SOA:
        return ("SOA", tuple(rr.owner.labels))
    return _rr_key(rr)


def answer_signature(ans: Answer):
    answer_sec = tuple(sorted(_rr_key(x) for x in ans.answer))
    authority_sec = tuple(sorted(_authority_key(x) for x in ans.authority))
    additional_sec = tuple(sorted(_rr_key(x) for x in ans.additional))
    return (
        ans.qtype, ans.rcode, ans.aa, ans.termination,
        answer_sec, authority_sec, additional_sec,
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

@dataclass
class TypeDiff:
    rdtype: int
    patterns: list[Pattern] = field(default_factory=list)
    changed_cells: int = 0
    total_cells: int = 0


def analyze(
    base_pz: ParsedZone,
    cand_pz: ParsedZone,
    qtypes: list[int],
) -> list[TypeDiff]:
    assert base_pz.origin == cand_pz.origin
    origin = base_pz.origin
    base_res, cand_res = Resolver(base_pz), Resolver(cand_pz)

    markers, fresh_map = build_markers(base_pz, cand_pz)
    cells = build_cells(markers, fresh_map)

    diffs: list[TypeDiff] = []
    for qt in qtypes:
        resolved: dict[tuple[str, tuple[str, ...]], tuple[Answer, Answer, Cell]] = {}
        for cell in cells:
            qname = abs_name(cell.probe, origin)
            a1 = base_res.resolve(qname, qt)
            a2 = cand_res.resolve(qname, qt)
            resolved[(cell.kind, cell.labels)] = (a1, a2, cell)

        changed_nodes = {
            labels
            for (kind, labels), (a1, a2, _) in resolved.items()
            if kind == "exact"
            and answer_signature(a1) != answer_signature(a2)
        }
        changed_star = {
            labels
            for (kind, labels), (a1, a2, _) in resolved.items()
            if kind == "star"
            and answer_signature(a1) != answer_signature(a2)
        }
        changed_deep = {
            labels
            for (kind, labels), (a1, a2, _) in resolved.items()
            if kind == "deep"
            and answer_signature(a1) != answer_signature(a2)
        }

        patterns = _emit_patterns(
            markers, resolved, changed_nodes, changed_star, changed_deep
        )
        diffs.append(TypeDiff(
            rdtype=qt,
            patterns=patterns,
            changed_cells=(
                len(changed_nodes) + len(changed_star) + len(changed_deep)
            ),
            total_cells=len(cells),
        ))
    return diffs


def _emit_patterns(markers, resolved, changed_nodes, changed_star, changed_deep):
    """生成互斥完备的模式。

    每个变化单元对应一个锥（exact / star / sub）。按从具体到宽泛的顺序
    发射；每个锥减去：

    1. 所有已发射、且位于其内部的更具体锥（应答确实变化的子区域）；
    2. 其名字集合内**应答未变**的已列名子区域——这些名字是探针空隙中的
       “空洞”：star 探针代表的是“未列名一标签下级 + 字面通配符”等价类，
       而已列名子节点各有独立签名；若通配符本身（空隙代表）发生变化而某
       个真实子节点（如已有精确 A 的 www）两版应答不变，它必须被显式
       排除，否则变化的 ``*.P`` 模式会错误地覆盖这个未变化的名字。

    从而保证：

    * 模式内任一 (名称,类型) 的两版应答都变化；
    * 模式外的名称要么应答未变，要么属于另一个模式；
    * 同一类型上全部模式两两不相交，且并集恰为“发生变化的名称集合”。
    """
    raw: list[tuple[int, Cone, Answer, Answer]] = []

    for node in changed_nodes:
        a1, a2, _ = resolved[("exact", node)]
        raw.append((len(node), Cone.exact(node), a1, a2))
    for node in changed_star:
        a1, a2, _ = resolved[("star", node)]
        raw.append((len(node), Cone.star(node), a1, a2))
    for node in changed_deep:
        a1, a2, _ = resolved[("deep", node)]
        raw.append((len(node), Cone.sub(node), a1, a2))

    # 深度优先：先具体后宽泛；同深度按标签排序保证输出稳定。
    raw.sort(key=lambda x: (-x[0], x[1].kind, x[1].labels))

    emitted: list[Cone] = []
    patterns: list[Pattern] = []
    for depth, cone, a1, a2 in raw:
        kind = {
            "exact": "exact", "star": "star", "sub": "deep"
        }[cone.kind]
        exclude = [c for c in emitted if _cone_within(c, cone)]

        P = cone.labels
        # 名字集合内“应答未变”的已列名空洞：探针空隙只代表未列名（+字面
        # 通配符）等价类，而已列名子节点各有独立应答，必须显式排除。
        if cone.kind in ("star", "sub"):
            for m in markers:
                is_star_name = bool(m) and m[0] == "*"

                if cone.kind == "star":
                    # *.P 只覆盖 P 的一标签下级，包括普通名 (L,)+P 与字面
                    # 星号名 (*,)+P——对名字 "*" 的查询是精确名查询
                    # （RFC 4592 2.1.1），不查通配 RRset，故它是空隙里独立
                    # 于通配符的空洞。其精确应答未变时排除 exact(m)。
                    if not (len(m) == len(P) + 1 and m[1:] == P):
                        continue
                    if m not in changed_nodes:
                        exclude.append(Cone.exact(m))
                    continue

                # cone.kind == "sub"（**.P，含 P 自身及任意多层下级）。
                # 字面 * 名只有在恰为某层一标签下级（(*,)+Q，Q 在 **.P 内）
                # 时是真实名字；* 出现在第二层及更深（如 (*, L,)+Q）不可
                # 能存在（通配符只能是最左标签），直接忽略。
                if is_star_name:
                    if (len(m) >= 2 and _suffix(m[1:], P)
                            and m not in changed_nodes):
                        exclude.append(Cone.exact(m))
                    continue
                if not _suffix(m, P):
                    continue
                # 普通标记点 m（精确应答未变时）：
                #   * m 的多层空层（deep 单元）变化 → 变化区域从 m 以下两层
                #     起步，排除精确点 exact(m)（一标签/深层变化各有独立、
                #     与之不相交的锥承载）；
                #   * 否则 m 的精确与多层单元都未变 → m 子树内若有变化也全
                #     在已发射的更深锥内，整体排除 sub(m)。
                if m not in changed_nodes:
                    if m in changed_deep:
                        exclude.append(Cone.exact(m))
                    else:
                        exclude.append(Cone.sub(m))

        # 排除列表去重并稳定排序。
        uniq: list[Cone] = []
        for c in sorted(exclude, key=lambda c: (c.kind, c.labels)):
            if c not in uniq:
                uniq.append(c)
        patterns.append(Pattern(
            scope=cone, exclude=uniq,
            witness=a1.qname, witness_kind=kind,
            baseline=a1, candidate=a2,
        ))
        emitted.append(cone)

    return patterns


def _suffix(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    """名称 child 是否以 parent 为右侧后缀（含相等）。"""
    return child == parent or (
        len(child) > len(parent) and child[len(child) - len(parent):] == parent
    )


def _depth_within(child: tuple[str, ...], parent: tuple[str, ...]) -> int:
    """child 比 parent 深几个标签；不是后缀时返回 -1。"""
    if not _suffix(child, parent):
        return -1
    return len(child) - len(parent)


def _cone_within(inner: Cone, outer: Cone) -> bool:
    """inner 名称集合是否包含于 outer 名称集合。

    名称集合语义（P 为锥的基准标签序列）：
      exact(P) = {P}
      star(P)  = 恰好比 P 深一层的名称（*.P，单层）
      sub(P)   = P 及其任意多层下级（**.P，零或多层）
    """
    P, Q = inner.labels, outer.labels
    if outer.kind == "exact":
        return inner.kind == "exact" and P == Q
    if outer.kind == "star":
        if inner.kind == "exact":
            return _depth_within(P, Q) == 1
        if inner.kind == "star":
            return P == Q
        return False  # sub 含零层/多层，不可能只落在单层
    # outer.kind == "sub"
    if inner.kind == "exact":
        return _depth_within(P, Q) >= 0
    if inner.kind == "star":
        # *.P 的全部名字都在 P 之下；P==Q 或 P 为 Q 下级时落入 sub(Q)。
        return _depth_within(P, Q) >= 0
    return _depth_within(P, Q) >= 0
