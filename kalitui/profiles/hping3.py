"""hping3 深度定制：主动网络探测（SYN/FIN/ACK/ICMP，仅安全探测模式）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "hping_probe",
            "description": (
                "用 hping3 做主动网络探测：SYN 半开探测、防火墙规则判断、端口状态验证。"
                "比 nmap 更灵活地构造包；常用于防火墙绕过测试和 ICMP 隧道检测。"
                "⚠ 注意：本封装仅提供单包探测模式（无洪水/DoS 能力）。外部目标需授权。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标 IP/域名"},
                    "mode": {
                        "type": "string",
                        "enum": ["syn", "ack", "fin", "icmp"],
                        "description": "包类型：syn=SYN 端口探测；ack=ACK 探测（判断防火墙）；fin=FIN 探测；icmp=ICMP echo",
                    },
                    "port": {"type": "integer", "description": "目标端口（icmp 模式忽略）"},
                    "count": {
                        "type": "integer",
                        "description": "发包数量（默认 3）",
                    },
                },
                "required": ["host", "mode", "port"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    mode = str(args.get("mode") or "syn").strip().lower()
    if mode not in ("syn", "ack", "fin", "icmp"):
        raise ValueError("mode 仅支持: syn / ack / fin / icmp")
    if mode == "icmp":
        return f"hping3 -1 -c {sanitize_int(args.get('count'), 3, 1, 20, 'count')} {host}", 30
    flag = {"syn": "-S", "ack": "-A", "fin": "-F"}[mode]
    port = sanitize_int(args.get("port"), 80, 1, 65535, "port")
    count = sanitize_int(args.get("count"), 3, 1, 20, "count")
    return f"hping3 {flag} -p {port} -c {count} {host}", 30


def _summarize(raw: str) -> str:
    replies = [
        l.strip()
        for l in raw.splitlines()
        if re.search(r"(flags=|len=)", l) and "hping3" not in l
    ]
    head: list[str] = []
    if replies:
        head.append("响应包（前 15 条）:")
        head += replies[:15]
    else:
        head = ["无响应（目标不可达/端口被过滤/防火墙丢弃）"]
    return ToolProfile._summary(raw, head, tail=30)


class Hping3Profile(ToolProfile):
    name = "hping3"
    aliases = ["hping3", "hping", "syn 探测", "防火墙测试", "半开扫描", "syn", "防火墙", "发包探测"]
    summary = "主动网络探测"
    lore = """### hping3 深度使用要点
- 定位：nmap 被防火墙干扰时的补充探测；构造特定包验证防火墙规则。
- 判读：SYN 探测收到 SYN-ACK = 端口开放；RST = 关闭；无响应 = 被过滤。
  ACK 探测收到 RST = 无状态防火墙（直接放行）；无响应 = 有状态防火墙（可疑开放）。
  FIN 探测（RFC 793 违规）收到 RST = 端口关闭；无响应 = 开放/被过滤。
- 本封装只做有限发包探测；--flood 等 DoS 能力刻意不提供。
- ICMP 模式可用于连通性 + 记录 TTL（判断主机系统类型）。"""
    extra_schemas = SCHEMAS

    async def exec_hping_probe(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("hping3"):
            return "hping3 未安装（apt install hping3）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
