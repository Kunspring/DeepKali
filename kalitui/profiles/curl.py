"""curl 深度定制：HTTP 请求封装（最常用的 Web 交互工具）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_req",
            "description": (
                "用 curl 发送 HTTP 请求并返回状态码/响应头/响应体摘要。"
                "Web 渗透最常用工具：看页面内容、测接口、带 cookie/header、POST 数据、跟随跳转。"
                "适合在 ffuf/gobuster 命中后验证路径内容。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "完整 URL，如 http://10.0.0.5/admin.php"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                        "description": "HTTP 方法（默认 GET）",
                    },
                    "data": {
                        "type": "string",
                        "description": "请求体（POST 等），如 'user=admin&pass=123'",
                    },
                    "headers": {
                        "type": "string",
                        "description": "自定义头，分号分隔，如 'Authorization: Bearer xyz; X-Forwarded-For: 127.0.0.1'",
                    },
                    "cookie": {"type": "string", "description": "Cookie，如 'session=abc123'"},
                    "follow": {
                        "type": "boolean",
                        "description": "跟随重定向（-L），默认 false",
                    },
                    "insecure": {
                        "type": "boolean",
                        "description": "跳过 TLS 证书校验（-k），默认 false",
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "响应体截断字节数（默认 4000，防输出爆炸）",
                    },
                },
                "required": ["url"],
            },
        },
    },
]

_URL_RE = re.compile(r"^https?://[^\s;|`$\\<>{}]{1,500}$", re.IGNORECASE)  # 允许 & 作为 query 分隔符
_HEADER_RE = re.compile(r"^[\w.-]+:\s*[^\r\n;]{1,200}(;\s*[\w.-]+:\s*[^\r\n;]{1,200}){0,9}$")
_DATA_RE = re.compile(r"^[\x20-\x7e]{0,4000}$")
_COOKIE_RE = re.compile(r"^[\w;=, .@-]{1,300}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    url = str(args["url"]).strip()
    if not _URL_RE.match(url):
        raise ValueError(f"url 格式非法（仅允许 http/https）: {url!r}")
    method = str(args.get("method") or "GET").strip().upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
        raise ValueError(f"method 仅支持: GET/POST/PUT/DELETE/HEAD/OPTIONS")
    data = str(args.get("data") or "").strip()
    if data and not _DATA_RE.match(data):
        raise ValueError("data 仅允许可打印 ASCII")
    headers = str(args.get("headers") or "").strip()
    if headers and not _HEADER_RE.match(headers):
        raise ValueError(f"headers 格式非法（应 'Name: value; Name2: value2'）: {headers!r}")
    cookie = str(args.get("cookie") or "").strip()
    if cookie and not _COOKIE_RE.match(cookie):
        raise ValueError(f"cookie 含非法字符: {cookie!r}")
    max_bytes = sanitize_int(args.get("max_bytes"), 4000, 500, 20000, "max_bytes")

    parts = ["curl", "-s", "-o", "/dev/stdout", "-w", "'\\n%{http_code} %{size_download}'", "--max-time", "20"]
    if method != "GET":
        parts += ["-X", method]
    if data:
        parts += ["--data-raw", shlex.quote(data)]
    if headers:
        for h in headers.split(";"):
            h = h.strip()
            if h:
                parts += ["-H", shlex.quote(h)]
    if cookie:
        parts += ["-b", shlex.quote(cookie)]
    if args.get("follow"):
        parts.append("-L")
    if args.get("insecure"):
        parts.append("-k")
    parts.append(shlex.quote(url))  # URL 含 & 必须 shell 引用
    return " ".join(parts), 40


def _summarize(raw: str) -> str:
    # 最后一行是 -w 输出的 状态码 大小
    lines = raw.splitlines()
    meta = lines[-1].strip() if lines else ""
    m = re.match(r"^(\d{3})\s+(\d+)$", meta)
    head: list[str] = []
    if m:
        code, size = m.group(1), m.group(2)
        icon = "✅" if code.startswith("2") else ("⚠️" if code.startswith(("3", "4")) else "🛑")
        head.append(f"{icon} HTTP {code}（{size} bytes）")
        body = "\n".join(lines[:-1]).strip()
        if body:
            head.append("响应体（截断）:")
            head += body.splitlines()[:25]
            if len(body.splitlines()) > 25:
                head.append(f"… 共 {len(body.splitlines())} 行")
    else:
        head = ["请求失败（连接被拒/超时/证书错误）"]
        head += lines[:10]
    return ToolProfile._summary(raw, head, tail=45)


class CurlProfile(ToolProfile):
    name = "curl"
    aliases = ["http 请求", "curl", "看页面", "接口测试", "web 请求", "访问网址", "看一下", "页面"]
    summary = "HTTP 请求工具"
    lore = """### curl 深度使用要点
- 定位：Web 渗透最基础工具——验证 fuzz 命中、看响应差异、测接口行为。
- 组合技：`-L` 跟跳转、`-k` 跳过证书、`-b` 带 cookie、`-H` 自定义头（X-Forwarded-For 绕过 IP 限制）。
- 测 SQL 注入/目录穿越先看响应差异（长度/状态码/关键字），再上 sqlmap。
- HEAD 方法快速看响应头（Server 版本、Set-Cookie 标志）；OPTIONS 看允许的方法。
- 传参注意：-X 指定方法；--data-raw 不解析 @ 文件（防意外读文件）。"""
    extra_schemas = SCHEMAS

    async def exec_http_req(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("curl"):
            return "curl 未安装（apt install curl）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
