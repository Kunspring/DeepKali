"""testssl.sh 深度定制：TLS 深度安全检测（比 sslscan 更详尽）。"""

from __future__ import annotations

import re
import shutil
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "tls_deep",
            "description": (
                "用 testssl.sh 对目标做深度 TLS 安全检测（协议、密码、证书、已知攻击向量）。"
                "比 ssl_scan 详尽：检测 BEAST/POODLE/Heartbleed/CRIME 等攻击面。"
                "检测慢（每项逐个测试），适合对重点目标深入评估。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标主机（可含端口，如 host:443）"},
                    "quick": {
                        "type": "boolean",
                        "description": "快速模式（只测协议和几个关键项），默认 true",
                    },
                    "protocols": {
                        "type": "boolean",
                        "description": "只测协议支持（最快），默认 false",
                    },
                },
                "required": ["host"],
            },
        },
    },
]


def _bin() -> str:
    for name in ("testssl", "testssl.sh"):
        if check_installed(name):
            return name
    for p in ("/usr/share/testssl.sh/testssl.sh", "/opt/testssl.sh/testssl.sh"):
        if __import__("os").path.exists(p):
            return p
    return ""


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = str(args["host"]).strip()
    if not re.fullmatch(r"[\w.:-]{1,255}", host) or re.search(r"[;&|`$\\\s]", host):
        raise ValueError(f"host 格式非法: {host!r}")
    quick = bool(args.get("quick", True))
    protocols = bool(args.get("protocols"))
    bin_ = _bin()
    parts = [bin_, "--quiet", "--color", "0"]
    if protocols:
        parts += ["-p"]
    elif quick:
        parts += ["--fast"]
    parts.append(host)
    return " ".join(parts), 600 if not quick else 300


def _summarize(raw: str) -> str:
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    results = [
        l for l in lines
        if re.match(r"^(SSLv|TLS|using|Testing|OK|NOT ok|local|chain|Heartbleed|BEAST|POODLE|CRIME)", l)
    ]
    weak = [l for l in results if re.search(r"(vulnerable|NOT ok|offered|expired)", l, re.IGNORECASE)]
    head: list[str] = []
    if results:
        head.append(f"TLS 检测结果（前 30）:")
        head += results[:30]
    if weak:
        head.append(f"⚠ 弱点项 ({len(weak)}):")
        head += weak[:10]
    if not head:
        head = ["检测无结果（主机不可达或非 TLS 端口）"]
    return ToolProfile._summary(raw, head, tail=45)


class TestsslProfile(ToolProfile):
    name = "testssl"
    aliases = ["testssl", "tls 深度", "tls 检测", "heartbleed", "poodle"]
    summary = "TLS 深度安全检测"
    lore = """### testssl.sh 深度使用要点
- 与 sslscan 区别：testssl.sh 逐个测试已知攻击向量（Heartbleed/BEAST/POODLE/CRIME/LUCKY13），输出详尽。
- 快速摸底用 --fast（协议+核心项）；重点目标做全量（慢，几分钟）。
- 只查协议支持用 -p；证书细节看 'chain'/'expired' 段。
- 弱点判读：'offered' 表示支持但非默认；'NOT ok' 是明确问题；'vulnerable' 立即报告。
- 适合对 ssl_scan 发现的弱配置做二次确认，产出报告用。"""
    extra_schemas = SCHEMAS

    async def exec_tls_deep(self, ex: Any, args: dict[str, Any]) -> str:
        bin_ = _bin()
        if not bin_:
            return "testssl.sh 未安装（apt install testssl.sh）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
