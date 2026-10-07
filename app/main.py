"""FastAPI 应用：DNS 区域变更影响 HTTP API。

端点：
* ``POST /impact``  —— 同域基线/候选两版区域，返回互斥完备的变更模式；
* ``POST /resolve`` —— 核对任意名称/类型在两版区域下的应答；
* ``GET  /healthz`` —— 存活探针。
"""
from __future__ import annotations

from typing import Optional

import dns.name
import dns.rdatatype
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .zone import parse_zone, ZoneError
from .resolver import Resolver
from .diff import analyze
from .serial import answer_to_json, pattern_to_json

SUPPORTED_TYPES = ("SOA", "NS", "A", "AAAA", "CNAME", "DNAME")
DEFAULT_TYPES = ("NS", "A", "AAAA", "CNAME", "DNAME")

app = FastAPI(
    title="DNS Zone Impact API",
    version="1.0.0",
    description=(
        "离线比较同域两份 BIND 区域文本（baseline / candidate），"
        "按响应码、RRset 与终止原因枚举域内全部名称在所列类型上的变更。"
    ),
)


class ImpactRequest(BaseModel):
    origin: Optional[str] = Field(
        default=None,
        description="区域起点（绝对域名）。缺省时由文本中的 SOA 推导。",
    )
    baseline: str = Field(..., description="基线版本 BIND 区域文本")
    candidate: str = Field(..., description="候选版本 BIND 区域文本")
    types: Optional[list[str]] = Field(
        default=None,
        description=(
            "要比较的类型列表；默认 NS/A/AAAA/CNAME/DNAME。"
            "始终允许 SOA。仅支持 SOA/NS/A/AAAA/CNAME/DNAME。"
        ),
    )


class ResolveRequest(BaseModel):
    origin: Optional[str] = None
    baseline: str
    candidate: str
    name: str = Field(..., description="要查询的名称（可相对 origin）")
    qtype: str = Field("A", alias="type")

    model_config = {"populate_by_name": True}


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
    )


def _parse_types(types: list[str] | None) -> list[int]:
    names = types if types is not None else list(DEFAULT_TYPES)
    if not names:
        raise ZoneError("types 不能为空")
    out: list[int] = []
    for t in names:
        tu = t.upper()
        if tu not in SUPPORTED_TYPES:
            raise ZoneError(
                f"不支持的类型 {t}；允许 {', '.join(SUPPORTED_TYPES)}"
            )
        try:
            val = dns.rdatatype.from_text(tu)
        except Exception as exc:
            raise ZoneError(f"类型非法: {t} ({exc})") from None
        if val not in out:
            out.append(val)
    return out


def _parse_pair(req) -> tuple:
    qtypes = _parse_types(getattr(req, "types", None))
    base = parse_zone(req.baseline, req.origin, label="baseline")
    # 先用 baseline 解析以确定 origin，再解析候选（保持报错顺序明确）。
    if req.origin is None:
        origin_text = base.origin.to_text()
    else:
        origin_text = req.origin
    cand = parse_zone(req.candidate, origin_text, label="candidate")
    if cand.origin != base.origin:
        raise ZoneError(
            f"两版区域起点不一致：{base.origin} vs {cand.origin}"
        )
    return base, cand, qtypes


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/impact")
def impact(req: ImpactRequest):
    try:
        base, cand, qtypes = _parse_pair(req)
    except ZoneError as exc:
        return _error(400, "invalid_zone", str(exc))

    diffs = analyze(base, cand, qtypes)
    patterns_out: list[dict] = []
    type_summaries = []
    total_changed_cells = 0
    total_cells = diffs[0].total_cells if diffs else 0

    for td in diffs:
        type_name = dns.rdatatype.to_text(td.rdtype)
        type_summaries.append({
            "type": type_name,
            "changed_cells": td.changed_cells,
            "patterns": len(td.patterns),
        })
        total_changed_cells += td.changed_cells
        for p in td.patterns:
            j = pattern_to_json(p, base.origin)
            j["types"] = [type_name]
            patterns_out.append(j)

    return {
        "origin": base.origin.to_text(),
        "compared_types": [dns.rdatatype.to_text(t) for t in qtypes],
        "coverage": {
            "probe_cells_per_type": total_cells,
            "changed_cells_total": total_changed_cells,
            "note": (
                "probe_cells_per_type 个等价类覆盖域内全部名称；"
                "每个模式的 scope 减去 exclude 后两两互斥且并集恰为变更集。"
            ),
        },
        "type_summary": type_summaries,
        "patterns": patterns_out,
    }


@app.post("/resolve")
def resolve(req: ResolveRequest):
    try:
        qtypes = _parse_types([req.qtype])
    except ZoneError as exc:
        return _error(400, "invalid_qtype", str(exc))
    qt = qtypes[0]

    try:
        base = parse_zone(req.baseline, req.origin, label="baseline")
        origin_text = base.origin.to_text() if req.origin is None else req.origin
        cand = parse_zone(req.candidate, origin_text, label="candidate")
    except ZoneError as exc:
        return _error(400, "invalid_zone", str(exc))

    try:
        qname = dns.name.from_text(req.name, origin=base.origin)
    except Exception as exc:
        return _error(400, "invalid_name", f"查询名非法: {req.name} ({exc})")

    if not qname.is_subdomain(base.origin):
        return _error(
            400, "out_of_zone",
            f"查询名 {qname} 不在区域 {base.origin} 内（服务离线，不联网）",
        )

    a1 = Resolver(base).resolve(qname, qt)
    a2 = Resolver(cand).resolve(qname, qt)
    from .diff import answer_signature
    same = answer_signature(a1) == answer_signature(a2)

    return {
        "origin": base.origin.to_text(),
        "qname": req.name,
        "qtype": dns.rdatatype.to_text(qt),
        "identical": same,
        "baseline": answer_to_json(a1, base.origin),
        "candidate": answer_to_json(a2, base.origin),
    }
