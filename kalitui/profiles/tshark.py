"""tshark 深度定制：抓包分析（Wireshark 命令行版，限时防挂起）。"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "tshark_capture",
            "description": (
                "用 tshark（Wireshark 命令行）抓包并做协议统计/会话摘要。"
                "比 tcpdump 更擅长协议解析：HTTP 请求、SMB 会话、DNS 查询一目了然。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "网卡（默认 any）",
                    },
                    "filter": {
                        "type": "string",
                        "description": "BPF 过滤，如 'tcp port 80'",
                    },
                    "seconds": {
                        "type": "integer",
                        "description": "抓包秒数（默认 15）",
                    },
                    "count": {
                        "type": "integer",
                        "description": "最多抓包数（默认 200）",
                    },
                    "display": {
                        "type": "string",
                        "description": "显示过滤器（可选），如 'http.request' 只看 HTTP 请求",
                    },
                },
                "required": [],
            },
        },
    },
]

_BPF_RE = re.compile(r"^[A-Za-z0-9 .'():/,&!<>\[\]*-]{1,200}$")
_DISPLAY_RE = re.compile(r"^[\w .():,!=<>\"'&|]{1,200}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    iface = str(args.get("interface") or "").strip()
    if iface and not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    bpf = str(args.get("filter") or "").strip()
    if bpf and not _BPF_RE.match(bpf):
        raise ValueError(f"filter 含非法字符（仅允许 BPF 语法）: {bpf!r}")
    display = str(args.get("display") or "").strip()
    if display and not _DISPLAY_RE.match(display):
        raise ValueError(f"display 含非法字符: {display!r}")
    seconds = sanitize_int(args.get("seconds"), 15, 3, 300, "seconds")
    count = sanitize_int(args.get("count"), 200, 1, 10000, "count")

    parts = ["timeout", str(seconds), "tshark", "-i", iface or "any"]
    if bpf:
        parts += ["-f", shlex.quote(bpf)]  # 命令经 bash 解析，BPF 空格必须引用
    parts += ["-c", str(count)]
    parts += ["-T", "fields", "-e", "frame.number", "-e", "_ws.col.Time", "-e", "_ws.col.Source",
              "-e", "_ws.col.Destination", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"]
    if display:
        parts += ["-Y", display]
    return " ".join(parts), seconds + 10


def _summarize(raw: str) -> str:
    rows = [
        l.strip()
        for l in raw.splitlines()
        if re.match(r"^\d+\t", l)  # 字段模式输出: 编号\t时间\t源\t目的\t协议\t信息
    ]
    head: list[str] = []
    if rows:
        head.append("抓包明细（前 30 条）:")
        head += rows[:30]
        if len(rows) > 30:
            head.append(f"… 共 {len(rows)} 条")
    else:
        head = ["未抓到包（网络空闲或过滤条件无匹配）"]
    return ToolProfile._summary(raw, head, tail=40)


class TsharkProfile(ToolProfile):
    name = "tshark"
    aliases = ["tshark", "wireshark", "协议分析", "抓包分析"]
    summary = "协议级抓包分析"
    lore = """### tshark 深度使用要点
- 与 tcpdump 区别：tshark 自带协议解析器，能直接看出 HTTP 方法、SMB 命令、DNS 类型。
- 显示过滤器（-Y）比 BPF 强大：`http.request`、`smb2.cmd == 5`、`dns.qry.name contains "admin"`。
- 找凭据：`-Y "http.authorization"` 或 `-Y "ftp.request.command == PASS"` 直接定位明文密码包。
- 分析已存 pcap：`tshark -r file.pcap -Y ...`（当前封装是实时抓取，pcap 分析可用 run_command）。
- 会话统计：`tshark -z conv,tcp`（需非字段模式，可 run_command 直接跑）。"""
    extra_schemas = SCHEMAS

    async def exec_tshark_capture(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("tshark"):
            return "tshark 未安装（apt install tshark）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
