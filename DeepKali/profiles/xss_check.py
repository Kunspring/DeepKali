"""XSS 反射检测：对 FUZZ 占位注入 5 种 payload，判定是否未编码反射。

白帽定位：反射型 XSS 验证——<script>/<img onerror>/<svg onload>/引号逃逸
变体，响应中 payload 原文未编码回显 = 反射候选（需结合上下文确认可利用）。
"""

from __future__ import annotations

import html
import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^[\x20-\x7e]{1,200}$")  # 可打印 ASCII

_DEFAULT_PAYLOADS: list[str] = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',       # 双引号属性逃逸
    "\'><script>alert(1)</script>",   # 单引号逃逸
    '<svg/onload=alert(1)>',          # 无空格变体（WAF 绕过）
]
_MAX_PAYLOADS = 15

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "xss_check",
            "description": (
                "反射型 XSS 验证：对 FUZZ 占位注入 5 种 payload（script/img onerror/"
                "svg onload/引号逃逸），判定响应是否未编码反射（候选）或已编码（安全）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "含 FUZZ 占位的 URL，如 "
                                       "http://t.com/search?q=FUZZ",
                    },
                    "payloads": {
                        "type": "array",
                        "description": "自定义 payload 列表（可选，追加到内置 5 种）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -m 15 '{url}'"


def _classify(raw: str, payload: str) -> str:
    """三态判定：raw / encoded / none。"""
    if payload in raw:
        return "raw"
    if html.escape(payload, quote=True) in raw:
        return "encoded"
    return "none"


def _summarize(results: list[tuple[str, str]]) -> str:
    raw_hits = [(p, raw) for p, raw in results if _classify(raw, p) == "raw"]
    encoded = [p for p, raw in results if _classify(raw, p) == "encoded"]
    head: list[str] = []
    if raw_hits:
        head.append(f"🚨 未编码反射 ({len(raw_hits)}/{len(results)}):")
        for p, raw in raw_hits:
            idx = raw.index(p)
            ctx = raw[max(0, idx - 30):idx + len(p) + 30].replace("\n", " ")
            head.append(f"  payload: {p}")
            head.append(f"    上下文: …{ctx}…")
        head.append("下一步：确认反射位置上下文（HTML 标签内/属性内/JS 内）→ 构造利用"
                    "（仅限授权）；修复：输出编码（HTML 实体）+ CSP。")
        if encoded:
            head.append(f"ℹ️ {len(encoded)} 个 payload 被编码（&lt;等）——该点已做输出编码，"
                        "但其他参数/位置需分别验证。")
    else:
        head.append("✅ 未发现未编码反射——输出已做编码（或参数不生效）。")
        if encoded:
            head.append(f"ℹ️ {len(encoded)} 个 payload 被 HTML 编码——反射点有编码防护，"
                        "试 JS 上下文/属性绕过（事件属性、javascript: 伪协议）。")
        head.append("提示：试更多注入点（Header/Referer/JSON 回显）、DOM XSS 需前端分析（secret_scan）。")
    return ToolProfile._summary("", head, tail=25)


class XssCheckProfile(ToolProfile):
    name = "xss_check"
    aliases = ["xss 检测", "反射 xss", "xss", "跨站脚本", "反射检测", "xss 验证"]
    summary = "反射型 XSS 检测"
    lore = """### XSS 检测使用要点
- 定位：搜索/参数回显点未编码 → 反射型 XSS（钓鱼/盗 cookie 常用）。
  FUZZ 占位写法：xss_check(url='http://t.com/search?q=FUZZ')。
- 5 种 payload：script 标签、img onerror、svg onload、双/单引号属性逃逸、
  无空格变体（WAF 绕过）。
- 判定：payload 原文未编码回显 = 候选（需看上下文确认可利用）；
  HTML 实体编码（&lt;script&gt;）= 该点有防护。
- 反射 ≠ 可利用：属性内需引号逃逸成功才成 XSS；JS 上下文（</script> 闭合）
  是另一类。输出上下文片段辅助判断。
- 结合流程：xss_check 命中 → 手工验证执行 → 配合 cookie 盗取/钓鱼场景评估；
  修复：上下文感知输出编码 + CSP + HttpOnly。
- 注意：只测 GET 反射；POST/JSON 回显需手工（curl -d 变体）；
  DOM XSS（前端 JS 处理）不在此范围。"""
    extra_schemas = SCHEMAS

    async def exec_xss_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法: {url!r}"
        if url.count("FUZZ") != 1:
            return "url 必须且只能包含一个 FUZZ 占位（如 http://t.com/search?q=FUZZ）。"
        payloads = list(_DEFAULT_PAYLOADS)
        extra = args.get("payloads") or []
        if not isinstance(extra, list):
            raise ValueError("payloads 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not _PAYLOAD_RE.match(p):
                raise ValueError("payload 含非法字符（仅允许可打印 ASCII）")
            if p not in payloads:
                payloads.append(p)
        if len(payloads) > _MAX_PAYLOADS:
            raise ValueError(f"payload 总数不能超过 {_MAX_PAYLOADS}")
        results: list[tuple[str, str]] = []
        for p in payloads:
            raw = await self._run(ex, _build_cmd(url.replace("FUZZ", p)), timeout=20)
            results.append((p, raw))
        return _summarize(results)
