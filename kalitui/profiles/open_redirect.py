"""开放重定向检测：对常见重定向参数注入外域值，看 Location 是否反射。

白帽定位：钓鱼链路的常见中危项——login?next=/redirect?url= 等参数若
未校验外域，可构造 http://target.com/login?next=http://evil.com 的钓鱼链接
（仿冒可信域名）。对 10 个常见参数名逐个实测，零依赖（curl）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")

# 常见重定向参数名
_PARAMS = [
    "url", "redirect", "redirect_url", "next", "return", "return_url",
    "dest", "target", "goto", "to",
]
_EVIL = "http://evil.com"
_MAX_PARAMS = 20

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "open_redirect",
            "description": (
                "开放重定向检测：对 10 个常见重定向参数（url/next/redirect 等）注入"
                "外域值，检测 Location 是否反射——钓鱼链接构造面。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://target.com/login",
                    },
                    "params": {
                        "type": "array",
                        "description": "自定义参数名列表（可选）",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str, param: str) -> str:
    sep = "&" if "?" in url else "?"
    return (
        f"curl -s -D - -o /dev/null -m 15 -w '\\n%{{http_code}}' "
        f"'{url}{sep}{param}={_EVIL}'"
    )


def _parse_location(raw: str) -> str:
    """提取 Location/Refresh 头值。"""
    for line in raw.splitlines():
        m = _HEADER_RE.match(line)
        if m and m.group(1).lower() in ("location", "refresh"):
            return m.group(2).strip()
    return ""


def _parse_code(raw: str) -> str:
    m = re.search(r"HTTP/\S+\s+(\d{3})", raw)
    return m.group(1) if m else ""


def _summarize(results: dict[str, tuple[str, str]]) -> str:
    hits = {p: (code, loc) for p, (code, loc) in results.items() if _EVIL in loc}
    head: list[str] = []
    if hits:
        head.append(f"🚨 开放重定向命中 ({len(hits)} 个参数):")
        for p, (code, loc) in hits.items():
            head.append(f"  [{code}] {p}={_EVIL} → Location: {loc[:80]}")
        head.append("下一步：确认该参数是否影响登录态/敏感流程（钓鱼链接构造面），修复需白名单校验。")
    else:
        head.append("✅ 未发现开放重定向（10 个常见参数均未反射外域）——"
                    "注意动态页面重定向（JS location）不在本检查范围。")
    return ToolProfile._summary("", head, tail=20)


class OpenRedirectProfile(ToolProfile):
    name = "open_redirect"
    aliases = ["开放重定向", "重定向检测", "钓鱼链接", "redirect 检测", "next 参数", "重定向漏洞"]
    summary = "开放重定向检测"
    lore = """### 开放重定向检测使用要点
- 定位：login?next=/redirect?url= 等参数未校验外域 → 可构造仿冒可信域名的钓鱼链接
  （如 target.com/login?next=http://evil.com 显示为可信域名开头）。
- 检查：对 10 个常见参数（url/redirect/next/return/dest/target/goto/to 等）注入
  http://evil.com，看 Location/Refresh 头是否反射。
- 判定：Location 含 http://evil.com → 命中；跳转到站内路径 → 安全；无 Location → 未命中。
- 结合流程：命中后配合社工/邮件钓鱼场景评估影响；修复：跳转目标白名单校验
  （协议+域名双重校验，禁止 // 协议相对跳转）。
- 注意：仅覆盖服务端 3xx 跳转；JS 动态跳转（window.location）需手工看前端代码。"""
    extra_schemas = SCHEMAS

    async def exec_open_redirect(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/login）: {url!r}"
        params = list(_PARAMS)
        extra = args.get("params") or []
        if not isinstance(extra, list):
            raise ValueError("params 必须是列表")
        for p in extra:
            p = str(p).strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", p):
                raise ValueError(f"参数名非法: {p!r}")
            if p not in params:
                params.append(p)
        if len(params) > _MAX_PARAMS:
            raise ValueError(f"参数总数不能超过 {_MAX_PARAMS}")
        results: dict[str, tuple[str, str]] = {}
        for p in params:
            raw = await self._run(ex, _build_cmd(url, p), timeout=20)
            results[p] = (_parse_code(raw), _parse_location(raw))
        return _summarize(results)
