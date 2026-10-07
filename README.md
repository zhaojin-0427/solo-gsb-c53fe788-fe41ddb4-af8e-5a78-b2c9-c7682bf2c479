# DNS 区域变更影响 HTTP API

用 **Python + FastAPI + dnspython** 实现的离线服务：给定同一区域的两份
BIND 文本（基线 `baseline` 与候选 `candidate`），枚举**域内所有名称**在
所列类型上的应答差异，输出一组**互斥且完备**的变更模式（change patterns），
每个模式都带一个见证名（witness）以及该名字在两版下的完整应答。

服务**完全离线**：不联网、不做递归；任何越区名称或外部引用都会让整单失败。

---

## 1. 能力与语义

* **只接受**记录类型 `SOA / NS / A / AAAA / CNAME / DNAME`，以及
  `$ORIGIN` / `$TTL` 两个指令；不支持 `$INCLUDE`。
* **整单报错**：非法语法 / 非法地址、越区属主、NS/CNAME/DNAME 指向区域外、
  CNAME 与其他类型共存、切点（cut）之下放置非 glue 数据、顶点放 CNAME/DNAME
  等，任一出现都会返回 `400`，不产生部分结果。
* 比较维度：**响应码（rcode）、RRset（忽略 TTL）、终止原因（termination）**。
* 终止原因区分：
  * `exact` 精确命中；
  * `wildcard_expansion` 最近包围名的直接下级通配符扩展（RFC 4592 的
    “源即合点”；通配 DNAME 还可按 RFC 6672 3.1.3 覆盖多层未列名）；
  * `delegation` 委派切点 referral（`AA=0`，authority 为 NS，glue 入 additional）；
  * `noerror_nodata` 精确名称有 RRset 但无该类型（含通配一层命中但无该类型）；
  * `ent_nodata` **空非终结点** NODATA：名字本身没有任何 RRset，但因为
    拥有普通后代而存在（存在性来自后代）；
  * `nxdomain` 名称不存在；
  * `alias_loop` / `alias_chain_limit` 别名环 / 跳数上限——**只标记**，不当错误。

### 名称存在性规则（关键）

解析器把“无 RRset 的节点”分成两类，二者不可混淆：

* **空非终结点（ENT）**：自身无 RRset，但在区域树里有**普通后代**（如只
  配置了 `deep.ent`，则 `ent` 是 ENT）。查询其名返回 `ent_nodata`；它参与
  最近包围名与通配源判定。
* **叶子的下级**：一个仅有自身 RRset 的名字（如新增叶子 `new`）**不会**
  让 `x.new` 变成存在节点——`x.new`、`a.x.new` 仍是 `nxdomain`，也不会
  凭空产生 `*.new` / `**.new` 变更。

最近包围名行走从查询名自身逐级向上，遇到的第一个“存在节点”（普通 RRset
属主、ENT、或通配属主的父节点，RFC 4592 A.1.1）即停：

* **深层未列名可命中最近包围名下的通配符**：`*.P` 能命中 `P` 的直接下级
  （即使 `P` 自身无数据）；通配 DNAME 还能合成多层未列名。
* **更近的存在节点阻断上层通配**：若 `leaf.e` 存在，则 `x.leaf.e` 的最近
  包围名是 `leaf.e` 而非顶点，`*.e` / 顶点 `*` 一律不再扩展 → NXDOMAIN。
* **CNAME / DNAME 逐跳重判**；DNAME 按 RFC 6672 在应答里合成一条 CNAME
  （合成 CNAME 在前、真实 DNAME 在后）。通配符 DNAME 也支持。
* **别名链跳数上限为 32 跳**（`MAX_ALIAS_HOPS`）：第 32 跳以
  `alias_chain_limit` 终止，末端数据不再可见；环以 `alias_loop` 终止。
* **DNAME 目标子树变化影响的“未列名”会被覆盖**：目标子树里的结构点会通过
  拉回（preimage）闭包映射回 DNAME 源侧，因此新增 `a.b.dt` 之类的变化会
  产生 `a.b.d` 等模式，而不会漏报。拉回深度**按实际跳数有限化**——一次拉回
  对应正向解析的一跳 DNAME 改写，闭包只生成“不超过 31 跳即可到达末端结构
  点”的源侧名称；再深的名字两版都在跳数上限处终止。这样即使区域里有
  `x.d DNAME d` 这种**自引用 DNAME**，闭包也只生成有限个 `x.d / x.x.d /
  … / x³¹.d` 标记（旧实现的无界不动点会在此无限生成、令 `/impact` 无响应），
  且边界与 `/resolve` 完全一致：31 层 `x` 的变化仍上报，32 层触顶后不报。

### 变更模式选择子（selector）

* `name`（exact）——单个名称，如 `www`、`@`；
* `*.prefix`（star，**一标签**）——prefix 的直接下级，恰好多一个标签；
* `**.prefix`（sub，**零或多层**）——prefix 本身及其任意多层下级。

每个模式 = `scope` **减去** `exclude` 列表里的子锥。同一类型上全部模式
两两不相交，且并集**恰好**等于“应答发生变化的全部名称”：

> 模式内任一 `(名称, 类型)` 的两版应答都不同；模式外任一名称都相同。

无限名称空间由“两版区域的标记名 trie + 每节点一对虚拟新鲜标签（`w-*`、
`ww-*`）”有限化，因此覆盖率可证明、可回归测试。

---

## 2. 一键启动（Docker Compose）

```bash
docker compose up --build -d
curl -s http://localhost:8080/healthz
# {"status":"ok"}
```

停止：

```bash
docker compose down
```

### 不用容器的本地启动

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

服务地址：`http://localhost:8080`，交互式文档：`/docs`（Swagger）、
`/redoc`（ReDoc）。

---

## 3. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/impact` | 提交两版区域，返回互斥完备的变更模式 |
| `POST` | `/resolve` | 核对任意一个名称/类型在两版下的应答 |
| `GET`  | `/healthz` | 存活探针 |

### `POST /impact` 请求字段

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `origin` | string | 否 | 区域起点绝对域名；缺省由文本 SOA/`$ORIGIN` 推导 |
| `baseline` | string | 是 | 基线 BIND 区域文本 |
| `candidate` | string | 是 | 候选 BIND 区域文本 |
| `types` | string[] | 否 | 默认 `NS,A,AAAA,CNAME,DNAME`；仅支持六类 |

### 与实现一致的真实请求

```bash
curl -sS http://localhost:8080/impact \
  -H 'Content-Type: application/json' \
  -d '{
    "origin": "example.",
    "types": ["A"],
    "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nwww A 192.0.2.10\napi A 192.0.2.20\n",
    "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nwww A 192.0.2.11\napi AAAA 2001:db8::20\nnew A 192.0.2.30\n"
  }'
```

这次改动：`www` 的 A 改了地址；`api` 删了 A（变成 NODATA）；新增了
叶子 `new`。

### 真实响应（完整含 3 个模式）

```json
{
  "origin": "example.",
  "compared_types": ["A"],
  "coverage": {
    "probe_cells_per_type": 15,
    "changed_cells_total": 3,
    "note": "probe_cells_per_type 个等价类覆盖域内全部名称；每个模式的 scope 减去 exclude 后两两互斥且并集恰为变更集。"
  },
  "type_summary": [ { "type": "A", "changed_cells": 3, "patterns": 3 } ],
  "patterns": [
    {
      "scope": { "selector": "api", "kind": "exact", "name": "api" },
      "exclude": [],
      "witness": { "name": "api", "probe_kind": "exact" },
      "baseline": {
        "qname": "api", "qtype": "A", "rcode": "NOERROR", "aa": true,
        "termination": "exact",
        "answer": [ { "name": "api", "type": "A", "ttl": 3600,
                      "records": [ { "address": "192.0.2.20" } ] } ],
        "authority": [], "additional": [],
        "wildcard_source": null, "dname_encloser": null, "alias_chain": []
      },
      "candidate": {
        "qname": "api", "qtype": "A", "rcode": "NOERROR", "aa": true,
        "termination": "noerror_nodata",
        "answer": [],
        "authority": [ { "name": "@", "type": "SOA", "ttl": 3600,
                         "records": [ { "mname": "ns1.example.",
                                        "rname": "hm.example.", "serial": 2,
                                        "refresh": 7200, "retry": 3600,
                                        "expire": 1209600, "minimum": 60 } ] } ],
        "additional": [],
        "wildcard_source": null, "dname_encloser": null, "alias_chain": []
      },
      "types": ["A"]
    },
    {
      "scope": { "selector": "new", "kind": "exact", "name": "new" },
      "exclude": [],
      "witness": { "name": "new", "probe_kind": "exact" },
      "baseline": { "termination": "nxdomain", "rcode": "NXDOMAIN",
                    "answer": [], "...": "..." },
      "candidate": {
        "termination": "exact", "rcode": "NOERROR",
        "answer": [ { "name": "new", "type": "A", "ttl": 3600,
                      "records": [ { "address": "192.0.2.30" } ] } ],
        "...": "..."
      },
      "types": ["A"]
    },
    {
      "scope": { "selector": "www", "kind": "exact", "name": "www" },
      "exclude": [],
      "witness": { "name": "www", "probe_kind": "exact" },
      "baseline": { "termination": "exact",
        "answer": [ { "name": "www", "type": "A", "ttl": 3600,
                      "records": [ { "address": "192.0.2.10" } ] } ], "...": "..." },
      "candidate": { "termination": "exact",
        "answer": [ { "name": "www", "type": "A", "ttl": 3600,
                      "records": [ { "address": "192.0.2.11" } ] } ], "...": "..." },
      "types": ["A"]
    }
  ]
}
```

**新增叶子只产生一个精确模式**：`new` 从 NXDOMAIN 变成精确命中；它**不会**
连带产生 `*.new` / `**.new`——`new` 是叶子，`x.new`、`a.x.new` 在候选版里
依旧是 NXDOMAIN（见下节 `/resolve` 示例）。这与“只配置 `new` 时其下级
不存在”的权威语义一致。

### 真实空非终结点与通配阻断（/impact）

```bash
curl -sS http://localhost:8080/impact \
  -H 'Content-Type: application/json' \
  -d '{
    "origin": "example.",
    "types": ["A"],
    "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\n*.e A 192.0.2.40\n",
    "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\n*.e A 192.0.2.40\nleaf.e A 192.0.2.41\ndeep.node.ent A 192.0.2.51\n"
  }'
```

候选版新增了两条记录：`leaf.e`（落在已有通配 `*.e` 下）与
`deep.node.ent`（全新多层名）。模式恰好为 5 个：

```text
deep.node.ent  nxdomain           -> exact            # 新叶子
node.ent       nxdomain           -> ent_nodata       # 因 deep.node.ent 成为 ENT
ent            nxdomain           -> ent_nodata       # 同上（两级祖先）
e              nxdomain           -> ent_nodata       # 通配父 *.e 现又有普通后代
leaf.e         wildcard_expansion -> exact            # 精确名压过通配
```

要点：

* `node.ent` / `ent` 自身没有任何 RRset，但因获得普通后代而成为**空非
  终结点**，对它们的查询由 NXDOMAIN 变为 `ent_nodata`；它们的其它下级
  （如 `x.node.ent`、`x.ent`）仍是 NXDOMAIN，不产生额外模式。
* 基线里 `e` 只是通配属主 `*.e` 的父节点（对 `e` 的查询是 NXDOMAIN）；
  候选版有了普通后代 `leaf.e` 后它升格为真实 ENT → `ent_nodata`。
* `leaf.e` 原本经 `*.e` 通配命中，加精确记录后变 `exact`；而 `x.leaf.e`
  的最近包围名是 `leaf.e`，上层 `*.e` 被阻断，仍为 NXDOMAIN。
* 只有“应答真的变化”的名字才进入模式集合；通配 / DNAME 覆盖的未列名区域
  用 `*.prefix` / `**.prefix` 表达，并在 `exclude` 中挖掉应答未变的已列名点。
### 自引用 DNAME 与跳数上限：`x.d DNAME d`（/impact 有限化）

区域里出现自引用 DNAME `x.d DNAME d` 时，查询
`a.x.d → a.x.x.d → a.x.x.x.d → …` 会沿着同一条 DNAME 规则逐跳改写。
下面两版区域只改了末端 `a.d` 的 A 地址（`192.0.2.10 → 192.0.2.20`）：

```bash
curl -sS http://localhost:8080/impact \
  -H 'Content-Type: application/json' \
  -d '{
    "origin": "example.",
    "types": ["A"],
    "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.10\n",
    "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.20\n"
  }'
```

反向拉回闭包按**实际跳数**有限化：`a.d`（0 跳）、`a.x.d`（1 跳）、……、
连续 31 层 `x` 的名字（31 跳）各产生一个精确模式——它们在 32 跳上限
**之前**仍能取到 `a.d` 变化后的 A；连续 32 层 `x` 及更深的名字两版都在
第 32 跳处以 `alias_chain_limit` 终止，末端 A 不可见，因此**不**产生模式，
也不会被误报。响应恰好 32 个模式（服务按先深后浅排序，最深的
`a.x³¹.d` 在 `patterns` 数组首位、`a.d` 在末尾）。下面是该请求的**真实
响应**，为便于叙述按 0 跳、1 跳、31 跳的顺序摘出三个见证（完整保留
0 跳与 1 跳两个模式；31 跳模式的长链只列真实的首/尾条目，重复部分用
`_note` / `_records_note` 键注明真实条数与内容——这些键仅为本文档可读性
加入，实际响应里是完整展开的记录）：

```json
{
  "origin": "example.",
  "compared_types": [
    "A"
  ],
  "coverage": {
    "probe_cells_per_type": 201,
    "changed_cells_total": 32,
    "note": "probe_cells_per_type 个等价类覆盖域内全部名称；每个模式的 scope 减去 exclude 后两两互斥且并集恰为变更集。"
  },
  "type_summary": [
    {
      "type": "A",
      "changed_cells": 32,
      "patterns": 32
    }
  ],
  "patterns": [
    {
      "scope": {
        "selector": "a.d",
        "kind": "exact",
        "name": "a.d"
      },
      "exclude": [],
      "witness": {
        "name": "a.d",
        "probe_kind": "exact"
      },
      "baseline": {
        "qname": "a.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.10"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": null,
        "alias_chain": []
      },
      "candidate": {
        "qname": "a.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.20"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": null,
        "alias_chain": []
      },
      "types": [
        "A"
      ]
    },
    {
      "scope": {
        "selector": "a.x.d",
        "kind": "exact",
        "name": "a.x.d"
      },
      "exclude": [],
      "witness": {
        "name": "a.x.d",
        "probe_kind": "exact"
      },
      "baseline": {
        "qname": "a.x.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.d.example."
              }
            ]
          },
          {
            "name": "x.d",
            "type": "DNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "d.example."
              }
            ]
          },
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.10"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": "x.d",
        "alias_chain": [
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.d.example.",
            "presented_cname_owner": "a.x.d"
          }
        ]
      },
      "candidate": {
        "qname": "a.x.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.d.example."
              }
            ]
          },
          {
            "name": "x.d",
            "type": "DNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "d.example."
              }
            ]
          },
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.20"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": "x.d",
        "alias_chain": [
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.d.example.",
            "presented_cname_owner": "a.x.d"
          }
        ]
      },
      "types": [
        "A"
      ]
    },
    {
      "scope": {
        "selector": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "kind": "exact",
        "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d"
      },
      "exclude": [],
      "witness": {
        "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "probe_kind": "exact"
      },
      "baseline": {
        "qname": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example."
              }
            ]
          },
          {
            "name": "x.d",
            "type": "DNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "d.example."
              }
            ],
            "_records_note": "真实应答中此 DNAME RRset 含 31 条完全相同的 {\"target\":\"d.example.\"} 记录（每经过一跳 x.d DNAME d 就在 answer 里呈现一次；此处为可读只列 1 条）。"
          },
          {
            "_note": "…其后是 30 条后续跳的合成 CNAME（无 DNAME），首/尾两条为：…"
          },
          {
            "name": "a.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.d.example."
              }
            ]
          },
          {
            "_note": "…中间 28 条：属主从 a.x^29.d 逐层到 a.x^2.d，target 各少一层 x…"
          },
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.10"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": "x.d",
        "alias_chain": [
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example.",
            "presented_cname_owner": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d"
          },
          {
            "_note": "真实 alias_chain 共 31 个元素，均为 {kind:\"DNAME\", owner:\"x.d\"}；target 依次为 a.x^30.d.example., a.x^29.d.example., …, a.d.example.，presented_cname_owner 依次为 a.x^31.d, a.x^30.d, …, a.x.d。"
          },
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.d.example.",
            "presented_cname_owner": "a.x.d"
          }
        ]
      },
      "candidate": {
        "qname": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "qtype": "A",
        "rcode": "NOERROR",
        "aa": true,
        "termination": "exact",
        "answer": [
          {
            "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example."
              }
            ]
          },
          {
            "name": "x.d",
            "type": "DNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "d.example."
              }
            ],
            "_records_note": "真实应答中此 DNAME RRset 含 31 条完全相同的 {\"target\":\"d.example.\"} 记录（每经过一跳 x.d DNAME d 就在 answer 里呈现一次；此处为可读只列 1 条）。"
          },
          {
            "_note": "…其后是 30 条后续跳的合成 CNAME（无 DNAME），首/尾两条为：…"
          },
          {
            "name": "a.x.d",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
              {
                "target": "a.d.example."
              }
            ]
          },
          {
            "_note": "…中间 28 条：属主从 a.x^29.d 逐层到 a.x^2.d，target 各少一层 x…"
          },
          {
            "name": "a.d",
            "type": "A",
            "ttl": 3600,
            "records": [
              {
                "address": "192.0.2.20"
              }
            ]
          }
        ],
        "authority": [],
        "additional": [],
        "wildcard_source": null,
        "dname_encloser": "x.d",
        "alias_chain": [
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example.",
            "presented_cname_owner": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d"
          },
          {
            "_note": "真实 alias_chain 共 31 个元素，均为 {kind:\"DNAME\", owner:\"x.d\"}；target 依次为 a.x^30.d.example., a.x^29.d.example., …, a.d.example.，presented_cname_owner 依次为 a.x^31.d, a.x^30.d, …, a.x.d。"
          },
          {
            "kind": "DNAME",
            "owner": "x.d",
            "target": "a.d.example.",
            "presented_cname_owner": "a.x.d"
          }
        ]
      }
    }
  ],
  "_patterns_note": "patterns 数组实际含 32 个模式，服务按先深后浅排序（数组首位即 31 跳的 a.x^31.d，末尾是 a.d）；为便于叙述此处按 0 跳(a.d)、1 跳(a.x.d)、31 跳(a.x^31.d) 的顺序摘出三个，中间 a.x^2.d … a.x^30.d 等 29 个结构与 31 跳模式相同而跳数递减。"
}
```

用 `/resolve` 直接核对边界（连续 31 层 `x` 仍变化；32 层触顶后两版一致）：

```bash
# 31 层 x：identical=false，两边都 31 跳、termination=exact，末端 A 不同
curl -sS http://localhost:8080/resolve -H 'Content-Type: application/json' -d '{
  "origin": "example.", "type": "A",
  "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
  "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.10\n",
  "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.20\n"
}'
# => "identical": false；baseline/candidate 的 termination 均为 "exact"，
#    alias_chain 各 31 个 DNAME 跳，answer 末端 A 分别为 .10 / .20

# 32 层 x：identical=true，两边均在第 32 跳终止
curl -sS http://localhost:8080/resolve -H 'Content-Type: application/json' -d '{
  "origin": "example.", "type": "A",
  "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
  "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.10\n",
  "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 7200 3600 1209600 60\n NS ns1\nns1 A 192.0.2.1\nx.d DNAME d\na.d A 192.0.2.20\n"
}'
```

第二请求的**真实响应**（同样用 `_note` 键折叠长链；实际响应完整展开）：
两边都是 32 跳 `alias_chain_limit`，answer 里只有逐跳的“合成 CNAME +
DNAME”，**没有**末端 A，因此 `identical` 为 `true`，该名字不属于任何模式：

```json
{
  "origin": "example.",
  "qname": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
  "qtype": "A",
  "identical": true,
  "baseline": {
    "qname": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
    "qtype": "A",
    "rcode": "NOERROR",
    "aa": true,
    "termination": "alias_chain_limit",
    "answer": [
      {
        "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "type": "CNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example."
          }
        ]
      },
      {
        "name": "x.d",
        "type": "DNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "d.example."
          }
        ],
        "_records_note": "真实应答中此 DNAME RRset 含 32 条完全相同的 {\"target\":\"d.example.\"} 记录（每经过一跳 x.d DNAME d 就在 answer 里呈现一次；此处为可读只列 1 条）。"
      },
      {
        "_note": "…其后是 31 条后续跳的合成 CNAME，最后一条为：…"
      },
      {
        "name": "a.x.d",
        "type": "CNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "a.d.example."
          }
        ]
      },
      {
        "_note": "链在第 32 跳终止；answer 到此结束，没有末端 a.d 的 A RRset。"
      }
    ],
    "authority": [],
    "additional": [],
    "wildcard_source": null,
    "dname_encloser": "x.d",
    "alias_chain": [
      {
        "kind": "DNAME",
        "owner": "x.d",
        "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example.",
        "presented_cname_owner": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d"
      },
      {
        "_note": "真实 alias_chain 共 32 个 DNAME 跳；第 32 跳 target 为 a.d.example.，resolver 在跳数上限处终止，不再查询 a.d。"
      }
    ]
  },
  "candidate": {
    "qname": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
    "qtype": "A",
    "rcode": "NOERROR",
    "aa": true,
    "termination": "alias_chain_limit",
    "answer": [
      {
        "name": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d",
        "type": "CNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example."
          }
        ]
      },
      {
        "name": "x.d",
        "type": "DNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "d.example."
          }
        ],
        "_records_note": "真实应答中此 DNAME RRset 含 32 条完全相同的 {\"target\":\"d.example.\"} 记录（每经过一跳 x.d DNAME d 就在 answer 里呈现一次；此处为可读只列 1 条）。"
      },
      {
        "_note": "…其后是 31 条后续跳的合成 CNAME，最后一条为：…"
      },
      {
        "name": "a.x.d",
        "type": "CNAME",
        "ttl": 3600,
        "records": [
          {
            "target": "a.d.example."
          }
        ]
      },
      {
        "_note": "链在第 32 跳终止；answer 到此结束，没有末端 a.d 的 A RRset。"
      }
    ],
    "authority": [],
    "additional": [],
    "wildcard_source": null,
    "dname_encloser": "x.d",
    "alias_chain": [
      {
        "kind": "DNAME",
        "owner": "x.d",
        "target": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d.example.",
        "presented_cname_owner": "a.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.d"
      },
      {
        "_note": "真实 alias_chain 共 32 个 DNAME 跳；第 32 跳 target 为 a.d.example.，resolver 在跳数上限处终止，不再查询 a.d。"
      }
    ]
  }
}
```

要点：

* 反向拉回深度上限 = `MAX_ALIAS_HOPS - 1`（31）：标记只覆盖“上限前还能
  看见末端”的名字，既不漏掉 31 层（含）以内的变化，也不把 32 层（含）
  以后触顶的名字误报；`/impact` 的每个见证应答都与 `/resolve` 对同一名字
  的应答逐字段相同（测试中有逐字段断言）。
* 只在一版出现的自引用 DNAME（如候选新增 `x.t DNAME t`）同样有限化：
  基线 `nxdomain` 与候选别名链/命中之间的真实变化由深度 0–31 的探针及其
  `*.…` / `**.…` 空隙模式承载，性质校验（变化名恰入一个模式、未变化名
  不入任何模式）在数万随机深名上通过。
* 非法语法、越区属主、外部 CNAME/NS/DNAME 目标等仍按整单 `400` 拒绝，
  与区域是否含自引用 DNAME 无关。


### 委派 / 通配 / DNAME 的应答长什么样

查询切点（如 `sub` 及其以下任意名称）时，无论什么类型都返回 referral：
`"aa": false`、`"termination": "delegation"`，`authority` 里是切点 NS，
`additional` 里是 glue。经通配符命中时 `termination` 为
`wildcard_expansion`，且 `wildcard_source` 给出真实通配属主（如 `*.wild`）。
经 DNAME 命中时，应答按线格式为 `[合成 CNAME, 真实 DNAME, ...目标 RRset]`，
`alias_chain` 逐跳给出 `kind / owner / target / presented_cname_owner`。

### `POST /resolve`：核对单个名称/类型

下面核对**新增叶子 `new` 后，其下级 `x.new` 是否被误判**：

```bash
curl -sS http://localhost:8080/resolve \
  -H 'Content-Type: application/json' \
  -d '{
    "origin": "example.",
    "name": "x.new", "type": "A",
    "baseline": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 1 1 1 1 1\n NS ns1\nns1 A 192.0.2.1\n",
    "candidate": "$ORIGIN example.\n$TTL 3600\n@ SOA ns1 hm 2 1 1 1 1\n NS ns1\nns1 A 192.0.2.1\nnew A 192.0.2.30\n"
  }'
```

响应（节选）：候选版只多了叶子 `new`，`x.new` 的最近包围名仍是顶点，
两版都是 **NXDOMAIN**，因此 `identical` 为 `true`——不会误报为
`ent_nodata`，也不会产生 `*.new` / `**.new` 模式：

```json
{
  "origin": "example.",
  "qname": "x.new",
  "qtype": "A",
  "identical": true,
  "baseline": {
    "qname": "x.new", "qtype": "A", "rcode": "NXDOMAIN", "aa": true,
    "termination": "nxdomain", "answer": [],
    "authority": [ { "name": "@", "type": "SOA", "ttl": 3600,
                     "records": [ { "mname": "ns1.example.",
                                    "rname": "hm.example.", "serial": 1,
                                    "refresh": 1, "retry": 1, "expire": 1,
                                    "minimum": 1 } ] } ],
    "additional": [],
    "wildcard_source": null, "dname_encloser": null, "alias_chain": []
  },
  "candidate": {
    "qname": "x.new", "qtype": "A", "rcode": "NXDOMAIN", "aa": true,
    "termination": "nxdomain", "answer": [],
    "authority": [ { "name": "@", "type": "SOA", "ttl": 3600,
                     "records": [ { "mname": "ns1.example.",
                                    "rname": "hm.example.", "serial": 2,
                                    "refresh": 1, "retry": 1, "expire": 1,
                                    "minimum": 1 } ] } ],
    "additional": [],
    "wildcard_source": null, "dname_encloser": null, "alias_chain": []
  }
}
```

对照：查询 `new` 本身，候选版从 `nxdomain` 变为 `exact`（`identical:false`）；
把 `name` 换成真实空非终结点（如仅配置 `deep.node.ent` 时查询 `node.ent`），
则得到 `termination: "ent_nodata"`。名称可相对 `origin`（`x.new`）或写绝对
名；解析到区域外返回 `400 out_of_zone`。

### 错误响应（整单拒绝）

非法 / 越区 / 外部引用统一形如：

```json
{ "error": { "code": "invalid_zone",
             "message": "baseline: 第 6 行外部引用——www 的 CNAME 目标 x.external. 不在区域 example. 内（服务离线，不联网解析）" } }
```

错误码：`invalid_zone`（区域文本问题）、`invalid_qtype`、`invalid_name`、
`out_of_zone`，HTTP 状态均为 `400`。

---

## 4. 项目结构

```
app/
  zone.py       # BIND 逐记录解析 + 越区/外部引用/委派校验；构建空非终结点/通配父节点集合
  resolver.py   # 离线权威解析：切点、最近包围名（含 ENT/通配父）、通配与 DNAME 合成、别名逐跳
  diff.py       # 标记 trie、按跳数有限化的 DNAME 拉回闭包（上限 31 跳）、探针分区、未列名空洞排除与互斥完备模式归并
  serial.py     # Answer / Pattern 的 JSON 序列化
  main.py       # FastAPI：POST /impact、POST /resolve、GET /healthz
tests/
  test_engine.py
Dockerfile
docker-compose.yml
requirements.txt
```

## 5. 测试

```bash
pip install pytest
PYTHONPATH=. python3 tests/test_engine.py     # 或：pytest -q
```

测试含数千个随机名称的性质校验：**变化名恰好落入一个模式、未变化名不落
入任何模式、模式之间互不重叠**，并覆盖通配 / DNAME（含目标子树未列名）/
ENT / 委派 / 别名环等情形。
