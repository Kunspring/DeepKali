"""HTTP 方法测试：OPTIONS 探测允许方法 + 高风险方法（PUT/DELETE/TRACE）实测。

白帽定位：Web 基础检查项——TRACE 开启可被 XST（跨站追踪）利用，
PUT/DELETE 开启可能允许直接上传/删除文件；OPTIONS 的 Allow 头先给清单，
再对高风险方法逐个实测状态码确认（Allow 头可能不可信）。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)
_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")
_RISKY = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_methods",
            "description": (
                "HTTP 方法测试：OPTIONS 看 Allow 清单，并对 PUT/DELETE/TRACE 等高风险"
                "方法实测状态码（TRACE 开启=XST 风险，PUT 允许=可上传文件）。"
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


def _build_cmd(url: str, method: str) -> str:
    return f"curl -s -X {method} -D - -o /dev/null -m 15 '{url}'"


def _parse_allow(raw: str) -> list[str]:
    """解析响应头中的 Allow 值 → 方法列表。"""
    for line in raw.splitlines():
        m = _HEADER_RE.match(line)
        if m and m.group(1).lower() == "allow":
            return [x.strip().upper() for x in m.group(2).split(",") if x.strip()]
    return []


def _parse_status(raw: str) -> str:
    """提取状态码（如 'HTTP/1.1 200 OK' → '200'），失败返回 ''。"""
    m = re.search(r"HTTP/\S+\s+(\d{3})", raw)
    return m.group(1) if m else ""


def _summarize(options_raw: str, probes: dict[str, str]) -> str:
    allow = _parse_allow(options_raw)
    head: list[str] = []
    head.append(f"📋 Allow 清单 ({len(allow)}): " + (", ".join(allow) if allow else "未返回 Allow 头"))
    risky: list[str] = []
    for m in _RISKY:
        code = _parse_status(probes.get(m, ""))
        if not code:
            continue
        if code.startswith(("2", "3")):
            risky.append(f"{m} → {code}（允许！）")
        else:
            head.append(f"  {m} → {code}（拒绝）")
    if risky:
        head.append("🚨 高风险方法可用:")
        head += [f"  - {r}" for r in risky]
        if "TRACE" in str(risky):
            head.append("  TRACE 开启 = XST 风险（配合 XSS 可窃取凭据）")
        if any(r.startswith("PUT") or r.startswith("DELETE") or r.startswith("PATCH") for r in risky):
            head.append("  可尝试上传/修改/删除文件（需确认认证与授权边界）")
        head.append("下一步：在授权范围内验证影响（PUT 上传 webshell 仅限靶场/授权目标）。")
    else:
        head.append("✅ 高风险方法均被拒绝（或服务器不响应）——方法配置较安全。")
    return ToolProfile._summary(options_raw, head, tail=25)


class HttpMethodsProfile(ToolProfile):
    name = "http_methods"
    aliases = ["http 方法", "方法测试", "options 探测", "xst", "put 测试", "trace 测试", "方法探测"]
    summary = "HTTP 方法测试（OPTIONS/TRACE/PUT/DELETE）"
    lore = """### HTTP 方法测试使用要点
- 定位：Web 基础检查项——TRACE 开启（XST）、PUT/DELETE 开启（任意上传/删除）是真实风险。
- 流程：OPTIONS 请求拿 Allow 头 → 对 PUT/DELETE/TRACE/PATCH/CONNECT 逐个实测状态码
  （Allow 头不可全信，实测为准：2xx/3xx=允许，405/403=拒绝）。
- XST：TRACE 开启 + 站点存在 XSS → 可绕过 HttpOnly 窃取 Cookie（需先有 XSS）。
- PUT 允许：授权靶场可试上传；真实目标仅验证存在性并记录，不实际写入。
- 注意：GET/POST/HEAD 必然允许，重点看额外方法；某些 WAF 会拦截 OPTIONS/TRACE，
  返回 403 时应标注"可能被 WAF 拦截"而非"安全"。"""
    extra_schemas = SCHEMAS

    async def exec_http_methods(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        url = str(args.get("url") or "").strip()
        if not _URL_RE.match(url):
            return f"url 格式非法（应如 http://target.com/）: {url!r}"
        options_raw = await self._run(ex, _build_cmd(url, "OPTIONS"), timeout=20)
        probes: dict[str, str] = {}
        for m in _RISKY:
            probes[m] = await self._run(ex, _build_cmd(url, m), timeout=20)
        return _summarize(options_raw, probes)
