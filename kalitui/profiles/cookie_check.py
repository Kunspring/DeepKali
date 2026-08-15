"""Cookie 安全属性审计：解析 Set-Cookie，检查 Secure/HttpOnly/SameSite 缺失。

白帽定位：SRC 常见低危项——会话 Cookie 缺 HttpOnly（XSS 可窃取）、
缺 Secure（HTTP 明文传输）、缺 SameSite（CSRF 防护弱化）、
SameSite=None 无 Secure（浏览器直接拒绝）。抓头解析零依赖。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_SETCOOKIE_RE = re.compile(r"^Set-Cookie:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_COOKIE_NAME_RE = re.compile(r"^([^=;]+)=")
_ATTR_RE = re.compile(r";\s*([A-Za-z][A-Za-z0-9]*)(?:=([^;]*))?")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "cookie_check",
            "description": (
                "Cookie 安全属性审计：解析 Set-Cookie 头，检查 HttpOnly/Secure/SameSite "
                "缺失——XSS 窃取/明文传输/CSRF 弱化风险判定。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://t.com/login",
                    },
                },
                "required": ["url"],
            },
        },
    },
]


def _build_cmd(url: str) -> str:
    return f"curl -s -D - -o /dev/null -m 15 '{url}'"


def _parse_cookies(raw: str) -> list[dict[str, Any]]:
    """解析 Set-Cookie 行 → [{name, attrs: {attr: value|True}}]。"""
    cookies: list[dict[str, Any]] = []
    for line in _SETCOOKIE_RE.findall(raw):
        line = line.strip()
        m = _COOKIE_NAME_RE.match(line)
        if not m:
            continue
        attrs: dict[str, Any] = {}
        for am in _ATTR_RE.findall(line):
            attrs[am[0].lower()] = am[1] if am[1] else True
        cookies.append({"name": m.group(1).strip(), "attrs": attrs})
    return cookies


def _analyze_cookie(c: dict[str, Any]) -> list[str]:
    """单个 cookie 的缺失项列表。"""
    a = c["attrs"]
    missing: list[str] = []
    if "httponly" not in a:
        missing.append("HttpOnly（JS 可读，XSS 时被窃取）")
    if "secure" not in a:
        missing.append("Secure（HTTP 明文下传输）")
    ss = a.get("samesite")
    if ss is True:
        missing.append("SameSite 无值（部分浏览器按 Lax 处理，需确认）")
    elif ss is None:
        missing.append("SameSite（CSRF 防护弱化，默认 Lax 覆盖有限）")
    if str(ss).lower() == "none" and "secure" not in a:
        missing.append("SameSite=None 但无 Secure——浏览器直接拒绝该 Cookie")
    return missing


def _summarize(raw: str, url: str) -> str:
    cookies = _parse_cookies(raw)
    head: list[str] = [f"🍪 {url} Cookie 审计（{len(cookies)} 个）:"]
    if not cookies:
        head.append("  （响应未返回 Set-Cookie——可能无需登录或会话在别处）")
        head.append("提示：先登录再测（带 cookie 访问受保护页）；WS/API 会话方式另行确认。")
    issues = 0
    for c in cookies:
        missing = _analyze_cookie(c)
        if missing:
            issues += len(missing)
            head.append(f"  ⚠️ {c['name']}: 缺 {'、'.join(missing)}")
        else:
            head.append(f"  ✅ {c['name']}: 属性齐全")
    if issues:
        head.append("下一步：会话 Cookie 缺 HttpOnly → XSS 即窃取会话；缺 Secure → "
                    "HTTP 明文链路可抓包；修复：HttpOnly+Secure+SameSite=Lax 三件套。")
    else:
        head.append("✅ 无缺失——Cookie 安全属性齐全（仍需确认会话固定/过期策略）。")
    return ToolProfile._summary(raw, head, tail=20)


class CookieCheckProfile(ToolProfile):
    name = "cookie_check"
    aliases = ["cookie 检查", "cookie 审计", "httponly", "会话 cookie", "cookie 安全", "samesite"]
    summary = "Cookie 安全属性审计"
    lore = """### Cookie 审计使用要点
- 定位：会话 Cookie 属性缺失是 SRC 常见低危项——HttpOnly/Secure/SameSite 三件套。
- 检查：抓 Set-Cookie 头解析每个 cookie 的属性（大小写不敏感）。
- 判定：缺 HttpOnly = JS 可读（XSS 直接窃取会话）；缺 Secure = HTTP 明文链路
  可抓包；缺 SameSite = CSRF 防护弱化；SameSite=None 无 Secure = 浏览器拒绝
  （业务功能实际受损）。
- 结合流程：cookie_check 发现问题 → 结合 xss_check（HttpOnly 缺失时 XSS 影响升级）
  /csrf_check（SameSite 缺失）→ 报告里按组合影响定级。
- 修复：Set-Cookie 统一加 HttpOnly; Secure; SameSite=Lax（跨站场景 None+Secure）。
- 注意：只测 GET 首页/登录页；登录后会话 cookie 需带凭据重测；
  子域 cookie（Domain=）影响范围扩大，Domain 属性也值得检查。"""
    extra_schemas = SCHEMAS

    async def exec_cookie_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://t.com/login）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=20)
        return _summarize(raw, url)
