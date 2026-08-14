"""airmon-ng 深度定制：无线网卡监控模式管理（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "wifi_monitor",
            "description": (
                "用 airmon-ng 查看/开启/关闭无线网卡监控模式。"
                "⚠ 危险操作：会触发确认弹窗（监控模式会中断该网卡正常联网）。"
                "监控模式是 wifi_crack/airodump 抓握手包的前置步骤。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["status", "start", "stop"],
                        "description": "status=查看状态；start=开启监控模式（需 interface）；stop=关闭",
                    },
                    "interface": {
                        "type": "string",
                        "description": "无线网卡名（如 wlan0；start 时必填）",
                    },
                },
                "required": ["action"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    action = str(args.get("action") or "status").strip().lower()
    if action not in ("status", "start", "stop"):
        raise ValueError("action 仅支持: status / start / stop")
    iface = str(args.get("interface") or "").strip()
    if iface and not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    if action == "start" and not iface:
        raise ValueError("start 必须指定 interface")
    if action == "status":
        return "airmon-ng", 30
    return f"airmon-ng {action} {iface}", 60


class AirmonProfile(ToolProfile):
    name = "airmon-ng"
    aliases = ["airmon", "监控模式", "无线网卡", "wifi 监听"]
    summary = "无线网卡监控模式管理"
    lore = """### airmon-ng 深度使用要点
- 定位：无线渗透前置——把网卡切到监控模式（mon0/monX）才能抓握手包。
- `airmon-ng`（status）先看网卡和驱动；有干扰进程（NetworkManager）先 kill。
- start 后网卡变名（如 wlan0 → wlan0mon），用新名字做 airodump-ng 抓包。
- 用完必须 stop 恢复联网（否则网卡一直不能正常上网）。
- 监听/破解流程：airmon start → airodump 抓包等握手 → wifi_crack 破解。"""
    extra_schemas = SCHEMAS

    async def exec_wifi_monitor(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("airmon-ng"):
            return "airmon-ng 未安装（apt install aircrack-ng）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        ifaces = [l.strip() for l in raw.splitlines() if re.match(r"^\S+\s+\S+.*(phy|monitor|wlan)", l)]
        head = []
        if ifaces:
            head.append("网卡状态:")
            head += ifaces[:15]
        else:
            head = ["未检测到无线网卡（或命令输出无匹配行）"]
        return self._summary(raw, head, tail=35)
