"""responder 深度定制：LLMNR/NBT-NS/mDNS 投毒分析（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "responder_analyze",
            "description": (
                "用 responder 分析当前网络的 LLMNR/NBT-NS/mDNS 流量（-A 分析模式，不投毒）。"
                "⚠ 危险操作：会触发确认弹窗。分析模式只监听不响应，相对安全；"
                "内网渗透时用分析结果判断哪些主机可能被投毒，再决定是否进入攻击模式。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "监听网卡（默认 eth0/wlan0 自动尝试）",
                    },
                    "seconds": {
                        "type": "integer",
                        "description": "分析时长秒数（默认 15）",
                    },
                },
                "required": [],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    iface = str(args.get("interface") or "").strip()
    if iface and not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    seconds = sanitize_int(args.get("seconds"), 15, 5, 120, "seconds")
    cmd = f"timeout {seconds} responder -I {iface or 'eth0'} -A"
    return cmd, seconds + 10


def _summarize(raw: str) -> str:
    reqs = [
        l.strip()
        for l in raw.splitlines()
        if re.search(r"\[(NBT-NS|LLMNR|MDNS|HTTP|SMB|WPAD)\]", l, re.IGNORECASE)
    ]
    if reqs:
        head = [f"捕获到协议请求 ({len(reqs)}):"]
        head += reqs[:30]
        head.append("提示：这些主机名请求可被投毒劫持（进入攻击模式前必须先确认授权）。")
    else:
        head = ["分析窗口内未捕获到可投毒请求（网络空闲或协议未启用）"]
    return ToolProfile._summary(raw, head, tail=40)


class ResponderProfile(ToolProfile):
    name = "responder"
    aliases = ["responder", "llmnr", "nbts", "投毒分析", "wpad"]
    summary = "LLMNR/NBT-NS 流量分析与投毒"
    lore = """### responder 深度使用要点
- 定位：内网横向阶段，收集 NetBIOS/LLMNR 名称解析请求 → 判断可投毒面。
- 分析模式（-A）只监听不响应，无副作用；攻击模式（默认）会响应请求并尝试抓取 NTLMv2 hash。
- 抓到 hash 后用 crack_hash（ntlmv2 类型）离线破解，或直接 relay（配合 ntlmrelayx）。
- WPAD 投毒可让内网主机回连你的 HTTP 服务，常用于抓取代理认证 hash。
- 高风险：攻击模式会改变内网解析行为，务必先确认测试授权范围。"""
    extra_schemas = SCHEMAS

    async def exec_responder_analyze(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("responder"):
            return "responder 未安装（apt install responder）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
