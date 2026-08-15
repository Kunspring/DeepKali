"""安全响应头与 CORS 检查：一次探测目标的关键安全头缺失与 CORS 反射风险。

白帽定位：Web 测试的基础检查项——点击劫持（缺 X-Frame-Options/CSP）、
HSTS 缺失、CORS 反射任意 Origin（可被跨域窃取数据）等，都是 SRC 常见提交项。
curl 抓响应头（-D - -o /dev/null），零外部依赖。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "header_check",
            "description": (
                "安全响应头与 CORS 检查：检查 X-Frame-Options/HSTS/CSP/X-Content-Type-Options "
                "缺失、CORS 是否反射任意 Origin、Server 指纹。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "目标 URL，如 http://target.com/",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

# (头名, 说明) —— 缺失即提示
_IMPORTANT = [
    ("X-Frame-Options", "点击劫持防护（缺省时需 CSP frame-ancestors 兜底）"),
    ("Content-Security-Policy", "CSP（缺省时点击劫持/注入面变大）"),
    ("Strict-Transport-Security", "HSTS（HTTPS 下缺失有降级风险）"),
    ("X-Content-Type-Options", "MIME 嗅探防护"),
    ("X-XSS-Protection", "XSS 过滤器（旧浏览器）"),
]


def _build_cmd(url: str, origin: str | None = None) -> str:
    extra = f" -H 'Origin: {origin}'" if origin else ""
    return f"curl -s -D - -o /dev/null -m 15{extra} '{url}'"


def _parse_headers(raw: str) -> dict[str, str]:
    """解析 'Name: value' 头行（忽略状态行/空行/续行）。"""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


def _summarize(raw: str, cors_raw: str) -> str:
    headers = _parse_headers(raw)
    cors_headers = _parse_headers(cors_raw)
    head: list[str] = []
    missing: list[str] = []
    for name, why in _IMPORTANT:
        if name.lower() not in headers:
            missing.append(f"{name}（{why}）")
    if missing:
        head.append(f"⚠ 缺失安全头 ({len(missing)}):")
        head += [f"  - {m}" for m in missing]
    else:
        head.append("✅ 关键安全头齐全（X-Frame-Options/CSP/HSTS 等）。")
    # CORS 检查
    acao = cors_headers.get("access-control-allow-origin")
    if acao:
        if "evil.com" in acao or acao.strip() == "*":
            head.append(
                f"🚨 CORS 风险: ACAO 反射/通配 ({acao})——跨域可读响应，"
                "若含敏感数据可被恶意站点窃取（需确认是否允许携带凭据）")
        else:
            head.append(f"ℹ️ CORS: ACAO 为固定值 {acao}（无反射风险）")
    else:
        head.append("✅ CORS: 无 Access-Control-Allow-Origin（默认同源策略保护）")
    server = headers.get("server")
    if server:
        head.append(f"🖥️ Server 指纹: {server}")
    head.append("下一步：缺失头可在服务端配置补齐；CORS 反射需结合数据敏感性评估。")
    return ToolProfile._summary(raw, head, tail=25)


class HeaderCheckProfile(ToolProfile):
    name = "header_check"
    aliases = ["安全头", "响应头", "cors 检查", "点击劫持", "hsts", "http 头", "头检查", "安全头检查"]
    summary = "安全响应头与 CORS 检查"
    lore = """### 安全响应头检查使用要点
- 定位：Web 测试基础项——一次请求查关键安全头缺失与 CORS 反射，SRC 常见低中危项。
- 检查项：X-Frame-Options/CSP（点击劫持）、HSTS（降级）、X-Content-Type-Options、
  X-XSS-Protection（旧浏览器）。
- CORS 检查：带 Origin: http://evil.com 发第二个请求，若 ACAO 回显 evil.com 即反射——
  配合凭据（cookies）可跨域读取响应数据，属真实风险；ACAO 为 * 且无凭据时风险较低。
- Server 头顺带指纹识别（nginx/apache/IIS + 版本），可接 cve_lookup 查已知漏洞。
- 注意：头缺失≠已利用，是配置缺陷；评估时结合业务敏感度。修复：服务端统一补头（nginx
  add_header / Apache Header set）。"""
    extra_schemas = SCHEMAS

    async def exec_header_check(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/）: {url!r}"
        raw = await self._run(ex, _build_cmd(url), timeout=20)
        cors_raw = await self._run(
            ex, _build_cmd(url, origin="http://evil.com"), timeout=20)
        return _summarize(raw, cors_raw)
