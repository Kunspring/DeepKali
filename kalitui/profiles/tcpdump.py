"""tcpdump 深度定制：抓包分析（限时/限数量，防止挂起）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "tcpdump_capture",
            "description": (
                "抓取网络流量并输出摘要（tcpdump）。"
                "适合验证服务连通性、观察攻击流量、排查网络问题。"
                "默认只抓前 50 个包或最多 20 秒，避免长时间挂起。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "网卡（默认自动选择，可用 ip a 查看）",
                    },
                    "filter": {
                        "type": "string",
                        "description": "BPF 过滤表达式，如 'tcp port 80' 或 'host 10.0.0.5'",
                    },
                    "count": {
                        "type": "integer",
                        "description": "最多抓多少个包（默认 50）",
                    },
                    "seconds": {
                        "type": "integer",
                        "description": "最多抓多少秒（默认 20）",
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "详细信息（-v，显示更多字段），默认 false",
                    },
                },
                "required": [],
            },
        },
    },
]

_BPF_RE = re.compile(r"^[A-Za-z0-9 .'():/,&!<>\[\]*-]{1,200}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    iface = str(args.get("interface") or "").strip()
    if iface and not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    bpf = str(args.get("filter") or "").strip()
    if bpf and not _BPF_RE.match(bpf):
        raise ValueError(f"filter 含非法字符（仅允许 BPF 语法）: {bpf!r}")
    count = sanitize_int(args.get("count"), 50, 1, 5000, "count")
    seconds = sanitize_int(args.get("seconds"), 20, 1, 300, "seconds")
    verbose = bool(args.get("verbose"))

    parts = ["timeout", str(seconds), "tcpdump"]
    if iface:
        parts += ["-i", iface]
    else:
        parts.append("-i")
        parts.append("any")
    if verbose:
        parts.append("-v")
    parts += ["-c", str(count), "-nn"]
    if bpf:
        parts.append("--")
        parts.append(bpf)
    return " ".join(parts), seconds + 10


def _summarize(raw: str) -> str:
    packets = [l.strip() for l in raw.splitlines() if re.match(r"^\d{2}:\d{2}:\d{2}", l)]
    stats = [l.strip() for l in raw.splitlines() if "packets captured" in l]
    head: list[str] = []
    if packets:
        head.append(f"抓包详情（前 25 条）:")
        head += packets[:25]
        if len(packets) > 25:
            head.append(f"… 共 {len(packets)} 条")
    if stats:
        head.append(stats[0])
    if not head:
        head = ["未抓到包（网络空闲或过滤条件无匹配）"]
    return ToolProfile._summary(raw, head, tail=40)


class TcpdumpProfile(ToolProfile):
    name = "tcpdump"
    aliases = ["抓包", "流量分析", "tcpdump", "网络抓包", "流量", "抓一下"]
    summary = "网络抓包与分析"
    lore = """### tcpdump 深度使用要点
- 常用过滤：`tcp port 80`、`host 10.0.0.5`、`tcp port 445`、`icmp`、`udp port 53`。
- 验证服务：对刚 nmap 发现的端口抓包，看服务是否真正响应/握手失败原因。
- 找凭据：抓 HTTP 明文（port 80）看 Authorization/表单密码；FTP/Telnet 同理。
- 抓包文件落盘用 `-w file.pcap`（当前封装是实时摘要；需要落盘可另用 run_command）。
- 大量抓包时加 -c 限制数量；怀疑有恶意流量时关注 SYN flood/异常大包。"""
    extra_schemas = SCHEMAS

    async def exec_tcpdump_capture(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("tcpdump"):
            return "tcpdump 未安装（apt install tcpdump）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
