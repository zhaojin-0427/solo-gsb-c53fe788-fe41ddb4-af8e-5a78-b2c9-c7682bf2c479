"""影响分析：把“域内所有名称 × 所列类型”切成有限等价类并比较两版应答。

名称集合（作用域）用三类锥表示（相对 ``$ORIGIN``）：

* ``exact(name)``：单个名称；
* ``star(prefix)``：``*.prefix`` —— prefix 的直接下级（恰好一个标签）；
* ``sub(prefix)``：``**.prefix`` —— prefix 本身及其任意多层下级
  （零或多个标签）。

无限名称空间通过“标记名 trie + 虚拟新鲜标签”有限化：

* 两版区域的全部真实属主、通配符父节点、空非终结点都作为标记；
* DNAME 目标子树的结构点通过拉回（preimage）闭包映射回源侧，
  因此 DNAME 目标变化影响到的未列名也会被覆盖；闭包受**两重**有限化：
  一次拉回对应正向解析的一跳 DNAME 改写，故按实际跳数限深
  （深度上限 ``MAX_ALIAS_HOPS - 1``），像 ``x.d DNAME d`` 这类自引用
  规则只生成有限个 x.d / x.x.d / … 标记；同时拉回产物必须是**合法
  DNS 名**（线格式不超过 255 字节）——DNAME 属主标签可达 63 字节，
  自引用规则每跳增加一个长标签，超过线长余量的反向标记一律不生成，
  它们对应“任何 DNS 报文都发不出去”的查询，不可能是合法见证；
* trie 上每个标记节点的直接下级空隙用一标签 / 两标签两个虚拟新鲜
  探针代表。探针标签按该节点的**线长余量**从全局最短新鲜标签池里
  分配：余量大时沿用 ``w-i`` / ``ww-i`` 风格；余量只容得下短标签时
  改取最短的新鲜标签（如 ``0``），保证“标记仍容得下短标签、却容不
  下常规虚拟标签”的空隙仍有合法见证；连一个标签都放不下（名字已到
  254/255 字节）时该空隙等价类本身为空，不建单元。名称永不截断。

输出模式形如 ``锥 − 排除子树列表``，同类型的模式互斥且并集覆盖全区域。
"""
from __future__ import annotations

import heapq
import itertools
import string
from dataclasses import dataclass, field

import dns.name
import dns.rdatatype

from .zone import ParsedZone
from .resolver import Resolver, Answer, MAX_ALIAS_HOPS

# 一个完整域名（绝对名）的线格式上限：255 字节（RFC 1035）。
MAX_NAME_WIRE = 255

# 反向拉回（preimage）的最大深度：一次拉回对应正向解析里的一跳 DNAME
# 改写。解析器在第 MAX_ALIAS_HOPS 跳处以 alias_chain_limit 终止，末端
# 数据不再可见；因此只需把“经不超过 MAX_ALIAS_HOPS-1 跳改写即可到达
# 末端结构点”的源侧名称拉成显式标记。再深的名字两版都在跳数上限处
# 终止，其变化判定由既有探针空隙承载——这与 /resolve 的逐跳结果一致：
# 31 层 x 仍能看到目标变化，32 层触顶后两版应答相同。
# 对 63 字节的长标签 DNAME 属主，线长上限会比跳数上限更早到达，届时
# 由线长检查截断（见 build_markers）：超长名在 DNS 里根本无法查询，
# 既不能当标记也不能当见证。
MAX_PREIMAGE_DEPTH = MAX_ALIAS_HOPS - 1


# ---------------------------------------------------------------------------
# 线长工具
# ---------------------------------------------------------------------------

def _label_wire(lb: str) -> int:
    return len(lb.encode("ascii", "strict")) + 1


def _rel_wire(labels: tuple[str, ...]) -> int:
    """相对标签序列拼回绝对名后占用的线字节数（不含根 0 字节）。"""
    return sum(_label_wire(lb) for lb in labels)


def _abs_wire(labels: tuple[str, ...], origin: dns.name.Name) -> int:
    """labels 相对 origin 拼回绝对名后的完整线格式长度（含根 0 字节）。"""
    return _rel_wire(labels) + len(origin.to_wire())


def _wire_room(labels: tuple[str, ...], origin: dns.name.Name) -> int:
    """该节点名下还能再放多少线字节（新增标签 = 标签长 + 1）。"""
    return MAX_NAME_WIRE - _abs_wire(labels, origin)


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
    # 调用方只应为合法（线长 ≤255）的探针名调用；这里若仍超限说明闭包 /
    # 单元构建的线长余量计算有误，直接作为程序错误抛出而非静默截断。
    if _abs_wire(labels, origin) > MAX_NAME_WIRE:
        raise dns.name.NameTooLong(
            f"内部探针名超过 {MAX_NAME_WIRE} 字节线格式上限，"
            "该空隙不应构建探针"
        )
    return dns.name.from_text(".".join(labels), origin=origin)


# ---------------------------------------------------------------------------
# 虚拟新鲜标签池
# ---------------------------------------------------------------------------

# 单标签线长上限 63 字节（1 长度字节 + 63 内容字节）。
_MAX_LABEL_LEN = 63
_FRESH_ALPHABET = string.digits + string.ascii_lowercase


def _short_labels():
    """最短新鲜标签序列：仅字母数字，按 (线长, 文本) 无限枚举。"""
    for n in itertools.count(1):
        if n > _MAX_LABEL_LEN:
            return
        for tup in itertools.product(_FRESH_ALPHABET, repeat=n):
            yield "".join(tup)


def _wide_labels():
    """常规 ``w-i`` / ``ww-i`` 风格虚拟标签序列，同样按 (线长, 文本)。"""
    for i in itertools.count():
        yield f"w-{i}"
        yield f"ww-{i}"


class FreshPool:
    """全局新鲜标签分配器。

    维护两族标签流：

    * **短标签**（``0``、``1``…字母数字名）——为线长余量极紧、放不下
      常规 ``w-i`` 风格标签的节点保留；
    * **宽标签**（``w-i`` / ``ww-i``）——余量充裕的节点使用，输出可读
      且与历史实现的探针命名保持一致。

    两族内部都按 ``(线长, 文本)`` 枚举；凡出现在两版区域真实标签里、
    字面 ``*`` 或已经被分配出去的标签都会被跳过（短/宽流共享同一占用
    集合），因此拿到的标签必为“未列名”，探针不会撞上真实属主。

    分配按节点线长余量**从紧到松**，每个节点先试探能否用一对宽标签
    同时放下 star 与 deep 两个探针（:meth:`take_wide_preferred`）；若
    宽 star 撑不下两层，就归还（:meth:`release`）并改用最短的短标签
    （:meth:`take_short_only`）——余量充裕的节点得到可读的
    ``w-i``/``ww-i``，只剩 2~3 字节的节点得到 ``0`` 之类一字符标签。
    """

    def __init__(self, forbidden: set[str]):
        self._used: set[str] = set(forbidden)
        self._used.add("*")
        self._streams = [iter(_short_labels()), iter(_wide_labels())]
        self._heaps: list[list[tuple[int, str]]] = [[], []]
        # 每个由本池取走的标签来自哪条流（release 时据此放回对应堆）。
        self._origin: dict[str, int] = {}
        for idx, it in enumerate(self._streams):
            self._advance(idx, it)

    def _advance(self, idx: int, it):
        try:
            lb = next(it)
        except StopIteration:
            return
        heapq.heappush(self._heaps[idx], (_label_wire(lb), lb))

    def _peek(self, idx: int):
        return self._heaps[idx][0] if self._heaps[idx] else None

    def _pop(self, idx: int) -> str:
        _wlen, lb = heapq.heappop(self._heaps[idx])
        self._advance(idx, self._streams[idx])
        return lb

    def _take_from(self, idx: int, max_wire: int) -> str | None:
        """从单条流里取一个线长 ≤ max_wire 的新鲜标签；放不下返回 None。"""
        while True:
            top = self._peek(idx)
            if top is None:
                return None
            wlen, lb = top
            if wlen > max_wire:
                return None
            self._pop(idx)
            if lb in self._used:
                continue
            self._used.add(lb)
            self._origin[lb] = idx
            return lb

    def take_short_only(self, max_wire: int) -> str | None:
        return self._take_from(0, max_wire)

    def take_wide_preferred(self, max_wire: int) -> str | None:
        # 严格优先宽标签：能放下任一宽标签就用宽的；只有余量连最短宽
        # 标签都放不下时才回落到短标签（此节点理应已在 tight 阶段处理，
        # 回落是双标签场景下第二标签的防御路径）。
        got = self._take_from(1, max_wire)
        if got is not None:
            return got
        return self._take_from(0, max_wire)

    def release(self, labels: list[str]) -> None:
        """归还一次试探性分配中已取走、最终不采用的标签。

        标签立即恢复为未占用并重新放回对应标签流的候选堆，因此随后的
        分配仍能拿到这些（最短的）名字——试探性的方案 A 失败不会“烧掉”
        本该属于方案 B 的短标签。
        """
        for lb in labels:
            self._used.discard(lb)
            heapq.heappush(
                self._heaps[self._origin.pop(lb)], (_label_wire(lb), lb)
            )


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
) -> tuple[set[tuple[str, ...]], FreshPool]:
    """返回 (标记名集合, 全局虚拟新鲜标签池)。

    所有标记都保证是合法 DNS 名：真实属主来自已校验区域（天然 ≤255），
    反向拉回产物在加入前按线长余量过滤——DNAME 属主为 63 字节长标签时，
    自引用拉回每跳增加 64 线字节，4 跳即超 255；超限名两版里都无法被
    任何 DNS 查询发出（``dns.name.from_text`` 直接 NameTooLong），故不
    作为标记，其“应答”也不能作为见证。合法查询空间由此仍被有限单元
    完备覆盖，且与 /resolve 的边界一致。
    """
    origin = base.origin
    markers = _collect_owner_labels(base, origin) | _collect_owner_labels(cand, origin)

    # DNAME 拉回闭包：两版区域里任一 DNAME 规则都要作用于当前全部标记，
    # 直到深度达到 MAX_PREIMAGE_DEPTH 或线长触顶。这样无论变化在源侧
    # 还是目标侧，受影响的未列名都会落进某个显式单元，而不是只被深层
    # 虚拟探针笼统覆盖。
    #
    # 有限化之一（跳数）：像 ``x.d DNAME d`` 这类自引用规则会把目标侧
    # 标记 d 拉成 x.d，再拉成 x.x.d……无深度限制便无限生成（旧实现的
    # 不动点循环在此直接挂死）。每个标记记录“经多少跳 DNAME 反向改写
    # 得到”的最短距离：属主/通配父节点为 0，每做一次拉回距离 +1；距离
    # 已达 MAX_PREIMAGE_DEPTH 的标记不再继续拉回。
    #
    # 有限化之二（线长）：拉回产物（绝对名）超过 255 字节线格式上限时
    # 不加入标记。它正向解析所需的查询名本身就无法在线上表达，不可能
    # 有合法见证；其所属合法名称空间的部分由父节点的 star/deep 探针
    # 空隙代表（空隙探针也按余量构建，见 build_cells）。
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
                if new in dist:
                    continue
                if _abs_wire(new, origin) > MAX_NAME_WIRE:
                    # 线长触顶：超长名无法查询，不作反向标记；它也不再
                    # 作为前沿继续拉回（更深的拉回只会更长）。
                    continue
                dist[new] = _depth + 1
                markers.add(new)
                new_frontier.add(new)
        frontier = new_frontier

    # trie 前缀闭合：合法标记的祖先标签数更少，线长必然也合法。
    for m in list(markers):
        for i in range(1, len(m)):
            markers.add(m[i:])

    # 全局虚拟新鲜标签池：避开两版区域的全部真实标签与字面 *。
    real_labels = {lb for m in markers for lb in m}
    pool = FreshPool(set(real_labels))
    return markers, pool


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
    pool: FreshPool,
    origin: dns.name.Name,
) -> list[Cell]:
    """为 trie 每个节点构建 exact/star/deep 单元。

    探针标签按节点线长余量从全局池中**从紧到松**分配：

    * 余量放不下任何一个合法标签（名字已达 254/255 字节）→ 该节点没有
      任何合法下级名，star/deep 等价类为空，只保留精确单元；
    * 只放得下一个一标签探针（余量 2~3 字节）→ 建 star 单元，取最短新
      鲜标签（如 ``0``）；deep 探针需要两个标签（至少 4 字节）放不下，
      该“多层未列名”等价类在合法名称空间里本就为空，不建单元；
    * 余量 ≥4 → star 与 deep 单元都建，deep 的两层标签都取新鲜名。

    探针名一律不截断；字面通配属主节点仍只建精确单元（其 star/deep
    空隙在语法上不可能存在）。
    """
    # 按线长余量从紧到松为每个节点分配探针标签，保证最短标签优先留给
    # 最紧的节点。标签选取在“保证 deep 等价类有见证”与“宽标签可读”间
    # 取舍：先试探能否用一对宽标签同时放下 star 与 deep 两个探针；若
    # 用宽 star 会撑掉 deep（而短 star 能保住 deep），就归还宽标签、
    # 改用最短短标签；余量连两层短标签都放不下时只建 star（该多层等
    # 价类在合法名称空间为空）。分配与单元产出分开，输出顺序不受影响。
    allocations: dict[tuple[str, ...], tuple[str | None, str | None]] = {}
    ordered = sorted(
        markers,
        key=lambda x: (_wire_room(x, origin), len(x), x),
    )
    for node in ordered:
        if node and node[0] == "*":
            allocations[node] = (None, None)
            continue
        room = _wire_room(node, origin)

        # 试探方案 A：star、deep 都用宽标签（w-i / ww-i 风格）。
        wide_star = pool.take_wide_preferred(room)
        wide_deep = (
            pool.take_wide_preferred(room - _label_wire(wide_star))
            if wide_star is not None else None
        )
        if wide_star is not None and wide_deep is not None:
            allocations[node] = (wide_star, wide_deep)
            continue
        # 方案 A 不完整（放不下两层宽探针，或连宽 star 都放不下）：归还，
        # 改走方案 B——用最短短标签优先保住合法等价类的覆盖。
        pool.release([lb for lb in (wide_star, wide_deep) if lb is not None])
        short_star = pool.take_short_only(room)
        short_deep = (
            pool.take_short_only(room - _label_wire(short_star))
            if short_star is not None else None
        )
        allocations[node] = (short_star, short_deep)

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
        star_label, deep_label = allocations[node]
        # 1) 精确单元（节点名本身合法——它要么来自区域，要么通过了线长检查）。
        cells.append(Cell("exact", node, node))
        # 2) 一标签空隙：node 的直接下级中不属于任何标记子节点的名字
        #    （其中包含字面 * 属主；新鲜标签 w 与之同属一个等价类）。
        if star_label is not None:
            cells.append(Cell("star", node, (star_label,) + node))
        # 3) 多层空隙：ww 开头，下面再放一层 w，代表“进入未标记子树后”
        #    的任意深度名称。
        if star_label is not None and deep_label is not None:
            cells.append(Cell("deep", node, (deep_label, star_label) + node))
    return cells


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

    markers, pool = build_markers(base_pz, cand_pz)
    cells = build_cells(markers, pool, origin)

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
