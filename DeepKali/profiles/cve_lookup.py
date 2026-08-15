"""CVE 情报查询：按编号查详情或按产品搜 CVE（cve.circl.lu 免费 API）。

白帽定位：nmap/joomscan/wpscan 识别出版本后，立刻查该产品的已知 CVE
（cvss 评分、公开利用状态），判断攻击面优先级——这是"发现→情报→验证"
链条的中间一环。
"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import ToolProfile, check_installed

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SEARCH_RE = re.compile(r"^[\w.\-]{1,64}$")  # vendor/product 名
_API = "https://cve.circl.lu/api"
_MAX_ROWS = 15

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "cve_lookup",
            "description": (
                "CVE 情报查询：传 cve_id（如 CVE-2024-1234）查详情（CVSS/描述/参考），"
                "或传 vendor+product（如 apache tomcat）按产品搜 CVE 列表。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE 编号，格式 CVE-YYYY-NNNN",
                    },
                    "vendor": {
                        "type": "string",
                        "description": "厂商名（与 product 一起用），如 apache",
                    },
                    "product": {
                        "type": "string",
                        "description": "产品名（与 vendor 一起用），如 tomcat",
                    },
                },
                "required": [],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> str:
    cve_id = str(args.get("cve_id") or "").strip()
    vendor = str(args.get("vendor") or "").strip()
    product = str(args.get("product") or "").strip()
    if cve_id:
        if not _CVE_RE.match(cve_id):
            raise ValueError(f"cve_id 格式非法（应如 CVE-2024-1234）: {cve_id!r}")
        return f"curl -s --max-time 20 '{_API}/cve/{cve_id.upper()}'"
    if vendor and product:
        if not _SEARCH_RE.match(vendor) or not _SEARCH_RE.match(product):
            raise ValueError("vendor/product 仅允许字母数字与 .-_")
        return f"curl -s --max-time 25 '{_API}/search/{vendor}/{product}'"
    raise ValueError("需要 cve_id 或 vendor+product（如 cve_lookup(vendor='apache', product='tomcat')）")


def _parse_detail(raw: str) -> dict[str, Any]:
    """解析 CVE 详情 JSON → 关键字段；非 JSON/空 → {}。"""
    try:
        data = json.loads(raw or "")
    except ValueError:
        return {}
    if not isinstance(data, dict) or "id" not in data:
        return {}
    cvss = data.get("cvss") or {}
    score = cvss.get("score") if isinstance(cvss, dict) else None
    return {
        "id": str(data.get("id", "")),
        "summary": str(data.get("summary") or "").strip(),
        "cvss": score if isinstance(score, (int, float)) else None,
        "cwe": str(data.get("cwe") or ""),
        "refs": len(data.get("references") or []),
        "published": str(data.get("Published") or ""),
    }


def _parse_search(raw: str) -> list[dict[str, Any]]:
    """解析产品搜索 JSON（列表）→ 前 _MAX_ROWS 条 (id, cvss, 摘要)。"""
    try:
        data = json.loads(raw or "")
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict) or "id" not in item:
            continue
        cvss = item.get("cvss") or {}
        score = cvss.get("score") if isinstance(cvss, dict) else None
        rows.append({
            "id": str(item.get("id", "")),
            "cvss": score if isinstance(score, (int, float)) else None,
            "summary": str(item.get("summary") or "").strip()[:90],
        })
    return rows[: _MAX_ROWS]


def _summarize(raw: str, args: dict[str, Any]) -> str:
    if args.get("cve_id"):
        d = _parse_detail(raw)
        if not d:
            head = ["未查到该 CVE（编号可能不存在或 API 不可达）"]
            return ToolProfile._summary(raw, head, tail=20)
        head = [f"🎯 {d['id']}"]
        if d["cvss"] is not None:
            sev = "严重" if d["cvss"] >= 9.0 else "高危" if d["cvss"] >= 7.0 else (
                "中危" if d["cvss"] >= 4.0 else "低危")
            head.append(f"CVSS: {d['cvss']}（{sev}）")
        if d["cwe"]:
            head.append(f"CWE: {d['cwe']}")
        if d["summary"]:
            head.append(f"描述: {d['summary'][:200]}")
        head.append(f"参考链接: {d['refs']} 条 | 发布时间: {d['published'][:10]}")
        head.append("下一步：若影响面匹配且可验证，用 sploit_search 找 PoC/exploit 再评估。")
        return ToolProfile._summary(raw, head, tail=25)
    rows = _parse_search(raw)
    if not rows:
        head = ["未搜索到该产品的 CVE（确认 vendor/product 拼写）"]
        return ToolProfile._summary(raw, head, tail=20)
    head = [f"🔎 产品 CVE 情报 ({len(rows)} 条，按 API 返回序):"]
    for r in rows:
        score = f"CVSS {r['cvss']}" if r["cvss"] is not None else "CVSS -"
        head.append(f"  {r['id']} [{score}] {r['summary']}")
    if len(rows) == _MAX_ROWS:
        head.append(f"… 共 {_MAX_ROWS}+ 条，按 cvss 排序后取前几条深入。")
    head.append("下一步：挑 CVSS 高分且与版本匹配的 CVE 查详情（cve_lookup）。")
    return ToolProfile._summary(raw, head, tail=30)


class CveLookupProfile(ToolProfile):
    name = "cve_lookup"
    aliases = ["cve 查询", "cve 情报", "漏洞编号", "cve 详情", "查 cve", "漏洞情报", "cve"]
    summary = "CVE 漏洞情报查询"
    lore = """### CVE 情报查询使用要点
- 定位：nmap/whatweb 识别出版本后，查已知 CVE 判断攻击面优先级——侦察与利用之间的情报环节。
- 按编号查：cve_lookup(cve_id='CVE-2024-1234') 拿 CVSS 评分/描述/CWE/参考链接。
- 按产品搜：cve_lookup(vendor='apache', product='tomcat') 列出该产品已知 CVE（默认前 15 条）。
- 数据源：cve.circl.lu 免费 API（无需 key）；若返回"未查到"可稍后重试或换 NVD 官网核对。
- 结合流程：版本指纹（whatweb/nmap -sV）→ cve_lookup 情报 → sploit_search 找利用 →
  手工验证（vuln_proof）→ 出报告。CVSS 高分 + 公开 PoC = 高优先级。
- 注意：CVSS 高分≠可利用；低分也可能组合利用。始终以实际验证为准。"""
    extra_schemas = SCHEMAS

    async def exec_cve_lookup(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        cmd = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=30)
        return _summarize(raw, args)
