"""JS 文件清单提取：抓页面提取全部外部 <script src>，归一化为完整 URL。

白帽定位：前端 JS 是逻辑/密钥/隐藏接口的高频泄露源——先列出页面加载的
全部外部脚本，再逐个 secret_scan 或手工审计（API 端点、硬编码凭据、
未发布功能开关）。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_SCRIPT_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_MAX_JS = 50

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "js_extract",
            "description": (
                "JS 文件清单提取：抓取页面提取全部外部 <script src>（归一化完整 URL，"
                "按同域/外域分组）——逐个 secret_scan 找硬编码密钥与隐藏接口。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标页面 URL，如 http://t.com/app",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _extract_scripts(raw: str, base: str) -> tuple[list[str], list[str]]:
    """提取外部 JS：返回 (同域列表, 外域列表)，已去重保序。"""
    same: list[str] = []
    external: list[str] = []
    seen: set[str] = set()
    base_host = urlparse(base).netloc
    for src in _SCRIPT_RE.findall(raw):
        src = src.strip()
        if not src or src.startswith(("data:", "blob:")):
            continue
        full = urljoin(base, src)
        if full in seen:
            continue
        seen.add(full)
        if urlparse(full).netloc == base_host:
            same.append(full)
        else:
            external.append(full)
    return same, external


def _summarize(raw: str, url: str) -> str:
    same, external = _extract_scripts(raw, url)
    total = len(same) + len(external)
    head: list[str] = [f"📜 {url} 外部 JS（{total} 个）:"]
    if same:
        head.append(f"  同域 ({len(same)}):")
        head += [f"    {s}" for s in same[:_MAX_JS]]
    if external:
        head.append(f"  外域 ({len(external)}):")
        head += [f"    {e}" for e in external[:15]]
        if len(external) > 15:
            head.append(f"    … 共 {len(external)} 个外域脚本")
    if total == 0:
        head.append("  （页面无外部脚本——SPA 可能用 module 内联或懒加载）")
        head.append("提示：抓取打包后 JS（/assets/app.xxxx.js，看 webpack 指纹）；"
                    "API 调用在 network 面板/JS 里，配合 secret_scan 全量扫。")
    else:
        head.append("下一步：同域 JS 逐个 secret_scan（密钥/接口）；外域脚本确认是否"
                    "第三方 SDK（信誉核查）或子域资产（api.cdn 等）。")
    return ToolProfile._summary(raw, head, tail=15)


class JsExtractProfile(ToolProfile):
    name = "js_extract"
    aliases = ["js 提取", "脚本清单", "js 文件", "前端审计", "script 提取", "js 列表"]
    summary = "JS 文件清单提取"
    lore = """### JS 提取使用要点
- 定位：前端 JS 泄露硬编码密钥/API 端点/隐藏功能——第一步列出所有外部脚本。
- 提取：<script src> 全部抓出 → urljoin 归一化完整 URL → 同域/外域分组去重。
- 结合流程：js_extract 列出清单 → 逐个 secret_scan（AK/SK、API key、token）→
  手动审计 API 调用（隐藏接口/未授权功能）→ 找 SPA 路由配置（权限前端口）。
- 外域脚本：确认第三方 SDK（Google/统计类正常）vs 子域资产（api.、cdn.——
  扩展攻击面）；异常外域 = 供应链风险。
- 注意：动态加载（import() 懒加载）不在初始 HTML 里；抓打包产物
  （/assets/*.js 用 web_leak/gobuster 找）；sourcemap（.js.map）可还原源码
  （secret_scan 支持时优先）。"""
    extra_schemas = SCHEMAS

    async def exec_js_extract(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/app）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=25)
        if len(raw) > 32768:
            raw = raw[:32768]
        return _summarize(raw, url)
