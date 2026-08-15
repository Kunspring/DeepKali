"""gau：历史 URL 收集（wayback/常见归档源，SRC 挖隐藏端点与敏感路径）。"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "gau",
            "description": (
                "用 gau（GetAllURLs）收集目标域在 wayback/归档数据源中出现过的"
                "历史 URL。SRC 隐藏资产侦察：旧端点、测试路径、备份文件、"
                "管理后台往往只存在于历史快照——别人扫过的痕迹就是你的线索。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "目标域名，如 example.com",
                    },
                },
                "required": ["domain"],
            },
        },
    },
]

_HIGH_VALUE = re.compile(
    r"(admin|login|api|\.git|\.env|backup|\.bak|\.sql|config|upload|debug|"
    r"console|swagger|test|stage|dev|old|v1/|phpmyadmin|wp-admin|actuator|"
    r"graphql|\.json|\.xml|\.tar|\.zip|\.sql.gz|id_rsa|\.pem|\.key)",
    re.IGNORECASE,
)


def _build_cmd(domain: str) -> str:
    return f"gau --threads 5 {domain}", 240


def _summarize(raw: str) -> str:
    urls: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.append(line)
    urls = list(dict.fromkeys(urls))
    if not urls:
        return ToolProfile._summary(raw, ["未收集到历史 URL（数据源无记录/域名无效）"], tail=15)
    high = [u for u in urls if _HIGH_VALUE.search(u)]
    domains = Counter(u.split("/")[2] for u in urls if len(u.split("/")) > 2)
    head = [
        f"🎯 历史 URL {len(urls)} 条（{len(domains)} 个主机）:",
    ]
    if high:
        head.append(f"  ⚠ 高价值 {len(high)} 条（admin/api/.git/.env/备份…）:")
        for u in high[:15]:
            head.append(f"    {u}")
        head.append("  验证：httpx 探活这些路径 → 存在的直接验证（未授权/信息泄露）；")
    else:
        head.append("  无高价值关键字命中，可整体探活后按需深入。")
    head.append(
        "  建议：配合 subfinder 把各子域都过一遍 gau；ffuf 在热门路径上深挖。"
    )
    return ToolProfile._summary(raw, head, tail=8)


class GauProfile(ToolProfile):
    name = "gau"
    aliases = ["历史 url", "gau", "url 收集", "wayback", "getallurls", "隐藏端点"]
    summary = "历史 URL 收集（wayback 等归档源）"
    lore = """### gau 深度使用要点
- 定位：被动侦察的"翻旧账"步。wayback/urlscan 等归档源保存了目标历史
  上的一切 URL——旧版端点、测试路径、泄露的备份文件。SRC 中很多
  高危发现（.git 泄露、admin 后台、actuator 端点）都来自这里。
- 用法：`gau example.com` 输出全部历史 URL；`--threads` 控制并发；
  子域逐个跑（gau 只收根域时配合 subfinder 列表循环）。
- 高价值模式：/api/、/admin、.git、.env、backup、.bak、.sql、
  actuator、graphql、swagger、.json/.xml/.tar/.zip——命中这些的 URL
  优先验证（httpx 探活 → http_req 看内容 → 信息泄露直接取证）。
- 联动：subfinder（找子域）→ gau（翻历史）→ httpx（探活）→
  ffuf/gobuster（在存活路径上深挖）→ nuclei（批量模板）。
- 注意：历史 URL 来自第三方归档，可能包含已下线或归属变更的资产，
  验证前确认当前归属仍在授权范围。"""
    extra_schemas = SCHEMAS

    async def exec_gau(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("gau"):
            return "gau 未安装（go install github.com/lc/gau/v2/cmd/gau@latest）。"
        domain = sanitize_target(str(args.get("domain") or ""))
        raw = await self._run(ex, *_build_cmd(domain))
        return _summarize(raw)
