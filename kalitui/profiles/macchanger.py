"""macchanger 深度定制：MAC 地址查看/修改（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "mac_change",
            "description": (
                "查看/修改网卡 MAC 地址（macchanger）。"
                "⚠ 危险操作：会触发确认弹窗（改 MAC 会中断该网卡连接，且修改网络身份有法律风险，仅授权测试用）。"
                "常用于无线渗透匿名化或绕过 MAC 白名单过滤。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "网卡名（如 wlan0/eth0）"},
                    "action": {
                        "type": "string",
                        "enum": ["show", "random", "set"],
                        "description": "show=查看当前；random=随机 MAC；set=指定 MAC",
                    },
                    "mac": {
                        "type": "string",
                        "description": "set 时指定 MAC，如 00:11:22:33:44:55",
                    },
                },
                "required": ["interface", "action"],
            },
        },
    },
]

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    iface = str(args.get("interface") or "").strip()
    if not re.fullmatch(r"[\w.-]{1,32}", iface):
        raise ValueError(f"interface 格式非法: {iface!r}")
    action = str(args.get("action") or "show").strip().lower()
    if action not in ("show", "random", "set"):
        raise ValueError("action 仅支持: show / random / set")
    mac = str(args.get("mac") or "").strip()
    if action == "set":
        if not _MAC_RE.match(mac):
            raise ValueError(f"mac 格式非法（应为 AA:BB:CC:DD:EE:FF）: {mac!r}")
        return f"macchanger -m {mac} {iface}", 60
    if action == "random":
        return f"macchanger -r {iface}", 60
    return f"macchanger -s {iface}", 30


class MacchangerProfile(ToolProfile):
    name = "macchanger"
    aliases = ["mac 修改", "macchanger", "改 mac", "匿名化"]
    summary = "MAC 地址管理"
    lore = """### macchanger 深度使用要点
- 定位：无线渗透/隐私匿名化——改 MAC 绕过 AP 白名单或避免被追踪。
- 顺序：先 `ip link set <iface> down` 再改 MAC 再 up（macchanger 会自动处理一部分）。
- 随机 MAC 会保留厂商前缀（-r 随机 OUI）；完全随机用 `-r` 后手动 -m。
- 注意：改 MAC 会断开当前连接；VM 环境改物理网卡无效（要改 VM 设置）。
- 改完用 `ip link show <iface>` 验证；恢复原 MAC 用 `macchanger -p <iface>`。"""
    extra_schemas = SCHEMAS

    async def exec_mac_change(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("macchanger"):
            return "macchanger 未安装（apt install macchanger）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        macs = [l.strip() for l in raw.splitlines() if "MAC" in l and ":" in l]
        head = macs[:10] if macs else [f"macchanger 执行完成（{args.get('action')}）"]
        return self._summary(raw, head, tail=30)
