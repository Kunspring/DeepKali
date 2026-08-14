"""netdiscover 深度定制：ARP 内网主机发现（被动/主动）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "net_discover",
            "description": (
                "用 netdiscover 做 ARP 主机发现（内网存活主机 + MAC 厂商指纹）。"
                "内网侦察第一步：比 nmap ping 扫描更快更隐蔽（ARP 不可路由但本地网段必答）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "range": {
                        "type": "string",
                        "description": "目标网段，如 192.168.1.0/24（默认本机网段）",
                    },
                    "interface": {"type": "string", "description": "网卡（可选）"},
                    "mode": {
                        "type": "string",
                        "enum": ["active", "passive"],
                        "description": "active=主动 ARP 请求（快，默认）；passive=被动监听（隐蔽）",
                    },
                    "seconds": {
                        "type": "integer",
                        "description": "扫描时长秒数（默认 15；passive 建议 60+）",
                    },
                },
                "required": [],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    rng = str(args.get("range") or "").strip()
    if rng:
        sanitize_target(rng)  # IP/CIDR 校验
    iface = str(args.get("interface") or "").strip()
    if iface and not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    mode = str(args.get("mode") or "active").strip().lower()
    if mode not in ("active", "passive"):
        raise ValueError("mode 仅支持: active / passive")
    seconds = sanitize_int(args.get("seconds"), 15, 5, 300, "seconds")

    parts = ["timeout", str(seconds), "netdiscover"]
    if iface:
        parts += ["-i", iface]
    if mode == "passive":
        parts.append("-p")
    if rng:
        parts += ["-r", rng]
    return " ".join(parts), seconds + 10


def _summarize(raw: str) -> str:
    hosts = [
        l.strip()
        for l in raw.splitlines()
        if re.match(r"^\d+\s+\d+\.\d+\.\d+\.\d+", l)
    ]
    head: list[str] = []
    if hosts:
        head.append(f"发现主机 ({len(hosts)}):")
        head += hosts[:30]
        if len(hosts) > 30:
            head.append(f"… 共 {len(hosts)} 条")
        head.append("下一步建议：对存活主机做 nmap 端口扫描。")
    else:
        head = ["未发现主机（网段无响应或需要 -r 指定范围）"]
    return ToolProfile._summary(raw, head, tail=40)


class NetdiscoverProfile(ToolProfile):
    name = "netdiscover"
    aliases = ["netdiscover", "arp 扫描", "主机发现", "内网扫描", "存活主机"]
    summary = "ARP 主机发现"
    lore = """### netdiscover 深度使用要点
- 定位：进入内网后第一步——找出所有存活主机；ARP 请求本地网段必答，比 ICMP 可靠。
- active 模式快（主动发包）；passive 模式纯监听更隐蔽（适合长期观察）。
- 输出含 MAC 厂商：能粗判设备类型（路由器/手机/VMware 虚拟机等）。
- 与 nmap 配合：netdiscover 找主机 → nmap 扫端口 → 定向深入。
- 本封装限时运行；大规模网段用 run_command 直接跑完整扫描更合适。"""
    extra_schemas = SCHEMAS

    async def exec_net_discover(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("netdiscover"):
            return "netdiscover 未安装（apt install netdiscover）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
