"""sslscan 深度定制：TLS 配置弱点扫描（证书/协议/密码套件）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ssl_scan",
            "description": (
                "用 sslscan 扫描目标 TLS 配置：支持的协议版本、密码套件、证书信息、弱点（如弱密码/过期证书）。"
                "Web/邮件服务器 TLS 配置评估用；发现 SSLv3/RC4/弱密钥及时报告。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标主机"},
                    "port": {
                        "type": "integer",
                        "description": "TLS 端口（默认 443；SMTP 465、IMAP 993 等）",
                    },
                    "sni": {
                        "type": "string",
                        "description": "SNI 主机名（可选，多域名证书时指定）",
                    },
                },
                "required": ["host"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = str(args["host"]).strip()
    if not re.fullmatch(r"[\w.:-]{1,255}", host) or re.search(r"[;&|`$\\\s]", host):
        raise ValueError(f"host 格式非法: {host!r}")
    port = sanitize_int(args.get("port"), 443, 1, 65535, "port", strict=True)
    sni = str(args.get("sni") or "").strip()
    if sni and not re.fullmatch(r"[\w.-]{1,255}", sni):
        raise ValueError(f"sni 格式非法: {sni!r}")
    parts = ["sslscan", "--no-colour", "--show-ciphers", f"{host}:{port}"]
    if sni:
        parts += ["--sni-name", sni]
    return " ".join(parts), 120


def _summarize(raw: str) -> str:
    proto = [l.strip() for l in raw.splitlines() if re.match(r"^\s*(SSLv|TLSv|Accepted)", l)]
    cert = [l.strip() for l in raw.splitlines() if re.search(r"(Subject:|Not valid|Issuer:)", l)]
    weak = [l.strip() for l in raw.splitlines() if re.search(r"(RC4|DES|3DES|NULL|EXPORT|SSLv2|SSLv3)", l, re.IGNORECASE)]
    head: list[str] = []
    if proto:
        head.append("支持的协议/套件（前 20）:")
        head += proto[:20]
        if len(proto) > 20:
            head.append(f"… 共 {len(proto)} 条")
    if cert:
        head.append("证书:")
        head += cert[:6]
    if weak:
        head.append(f"⚠ 发现弱点配置 ({len(weak)} 条):")
        head += weak[:10]
    if not head:
        head = ["扫描无结果（主机不可达或端口未开 TLS）"]
    return ToolProfile._summary(raw, head, tail=40)


class SslscanProfile(ToolProfile):
    name = "sslscan"
    aliases = ["ssl 扫描", "tls 检查", "sslscan", "证书检查", "密码套件", "tls 配置", "ssl 配置"]
    summary = "TLS 配置弱点扫描"
    lore = """### sslscan 深度使用要点
- 定位：评估目标 TLS 安全配置；报告过时协议（SSLv3/SSLv2）、弱密码（RC4/3DES）、证书问题。
- 对比 testssl.sh：sslscan 快但浅；testssl.sh 输出更详尽（含 BEAST/POODLE 等攻击检测）。
- 关注：SSLv3（POODLE）、RC4（BEAST）、证书过期/自签名/CN 不匹配。
- 邮件端口：465(SMTPS)/993(IMAPS)/995(POP3S) 都要扫；非标准端口直接指定。
- 结果用于报告和漏洞利用（如弱密码可离线破解 TLS 会话）。"""
    extra_schemas = SCHEMAS

    async def exec_ssl_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("sslscan"):
            return "sslscan 未安装（apt install sslscan）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
