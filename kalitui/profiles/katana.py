"""katana：JS 端点爬虫（前端路由/API 端点提取，SPA 应用侦察利器）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "katana",
            "description": (
                "用 katana 爬取目标站点并提取 JS 文件中的端点（API 路由/前端"
                "路径）。SPA 应用的隐藏 API 端点大多只存在于 JS bundle 里——"
                "gau 翻历史，katana 扒当前，两者互补。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://example.com",
                    },
                    "js_only": {
                        "type": "boolean",
                        "description": "只从 JS 文件提取端点（默认 true）",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "爬取深度 1-10（默认 3）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(
    r"^https?://[^\s/;|`$(){}\[\]]+(?:/[^\s;|`$(){}\[\]]*)?$", re.IGNORECASE
)
_ENDPOINT_RE = re.compile(
    r"(/api/[\w./{}$?=&:-]+|/v\d/[\w./{}$?=&:-]+|/admin[\w./-]*|"
    r"/graphql|/actuator[\w./-]*|/internal[\w./-]*)",
    re.IGNORECASE,
)


def _build_cmd(url: str, js_only: bool, depth: int) -> str:
    parts = ["katana", "-u", url, "-d", str(depth), "-silent"]
    if js_only:
        parts.append("-jc")  # 只解析 JS 端点
    return " ".join(parts), 300


def _summarize(raw: str) -> str:
    urls: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.append(line)
    urls = list(dict.fromkeys(urls))
    if not urls:
        return ToolProfile._summary(raw, ["未提取到端点（JS 不可达/无 JS 应用/被拦截）"], tail=15)
    high = [u for u in urls if _ENDPOINT_RE.search(u)]
    head = [
        f"🎯 提取端点 {len(urls)} 条:",
    ]
    if high:
        head.append(f"  ⚠ 高价值 API/管理端点 {len(high)} 条:")
        for u in high[:20]:
            head.append(f"    {u}")
    else:
        head.append("  无 /api//admin/ 等关键字，可整体探活后抽查。")
    head.append("  验证：httpx 探活 → 对存活 API 试未授权访问/参数注入（授权内）。")
    return ToolProfile._summary(raw, head, tail=8)


class KatanaProfile(ToolProfile):
    name = "katana"
    aliases = ["爬虫", "katana", "js 端点", "端点提取", "spa 侦察", "前端路由"]
    summary = "JS 端点爬取提取"
    lore = """### katana 深度使用要点
- 定位：SPA 应用（Vue/React）的 API 端点大多藏在 JS bundle 里，
  页面源码看不到。katana -jc 只爬 JS 并提取端点——登录后的功能、
  隐藏管理 API、内部服务路由都在这里。
- 用法：`katana -u http://target -jc -silent`（-jc 只解析 JS 端点）；
  `-d 3` 控制深度（默认 3 够用，太深会触发告警）。
- 高价值模式：/api/、/v1//v2/、/admin、/graphql、/actuator（Spring Boot
  健康接口泄露）、/internal——命中即优先验证未授权访问。
- 联动：gau（历史 URL）+ katana（当前 JS 端点）合并去重 →
  httpx 探活 → 对存活端点做未授权/参数测试 → 发现即证据入库。
- 注意：爬虫产生大量请求，外网目标限制并发与深度；JS 文件可能被
  CDN 缓存，验证时注意当前版本与抓取版本差异。"""
    extra_schemas = SCHEMAS

    async def exec_katana(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("katana"):
            return "katana 未安装（go install github.com/projectdiscovery/katana/cmd/katana@latest）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            raise ValueError(f"url 必须是完整 URL（含 http/https）: {url!r}")
        js_only = bool(args.get("js_only", True))
        depth = args.get("depth") or 3
        try:
            depth = int(depth)
        except (TypeError, ValueError):
            raise ValueError(f"depth 必须是整数: {depth!r}") from None
        if not 1 <= depth <= 10:
            raise ValueError(f"depth 超出范围: {depth}")
        raw = await self._run(ex, *_build_cmd(url, js_only, depth))
        return _summarize(raw)
