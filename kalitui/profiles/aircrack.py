"""aircrack-ng 深度定制：WPA/WPA2 握手包离线破解（危险操作，触发确认）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_wordlist,
)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "wifi_crack",
            "description": (
                "用 aircrack-ng 离线破解 WPA/WPA2 握手包（.cap 文件）。"
                "⚠ 危险操作：会触发确认弹窗；只允许破解你自己网络/授权测试的握手包。"
                "握手包通常来自 airodump-ng 抓包（WPA handshake: COMPLETE 时抓取）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "capture": {
                        "type": "string",
                        "description": "握手包 .cap/.pcap 文件路径（/root 或 /tmp 下）",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "字典路径（默认 /usr/share/wordlists/rockyou.txt）",
                    },
                    "bssid": {
                        "type": "string",
                        "description": "指定目标 AP 的 BSSID（多 AP 抓包时用），如 AA:BB:CC:DD:EE:FF",
                    },
                },
                "required": ["capture"],
            },
        },
    },
]

_CAP_RE = re.compile(r"^/[\w./-]+\.(cap|pcap|hccapx)$")
_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    cap = str(args.get("capture") or "").strip()
    if not _CAP_RE.match(cap):
        raise ValueError("capture 必须是 /root 或 /tmp 下的 .cap/.pcap 文件路径")
    if not Path(cap).exists():
        raise ValueError(f"握手包文件不存在: {cap}")
    wordlist = sanitize_wordlist(str(args.get("wordlist") or "/usr/share/wordlists/rockyou.txt"))
    bssid = str(args.get("bssid") or "").strip()
    if bssid and not _BSSID_RE.match(bssid):
        raise ValueError(f"bssid 格式非法（应为 AA:BB:CC:DD:EE:FF）: {bssid!r}")

    parts = ["aircrack-ng", "-w", wordlist, "-b", bssid, cap] if bssid else ["aircrack-ng", "-w", wordlist, cap]
    return " ".join(parts), 900


class AircrackProfile(ToolProfile):
    name = "aircrack"
    aliases = ["wifi 破解", "无线破解", "握手包", "wpa 破解", "aircrack"]
    summary = "WPA 握手包离线破解"
    lore = """### aircrack-ng 深度使用要点
- 前置：先用 airodump-ng 监听抓包，等到 `WPA handshake: COMPLETE`（客户端重连或 deauth 触发）。
- 破解是纯离线计算，字典质量决定成败：rockyou 全量 → 加规则变形 → 换 GPU（hashcat -m 22000）。
- 多 AP 的抓包文件用 bssid 指定目标；WPA3 无法用此法破解（用 dragonblood 类攻击需授权）。
- 破解出的密码立即验证登录路由器/同名 SSID 复用（很多人多设备同名同密码）。"""
    extra_schemas = SCHEMAS

    async def exec_wifi_crack(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("aircrack-ng"):
            return "aircrack-ng 未安装（apt install aircrack-ng）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        # 命中格式: KEY FOUND! [ password ]
        hit = re.search(r"KEY FOUND!\s*\[\s*([^\]]+?)\s*\]", raw)
        if hit:
            head = [f"🎯 WPA 密码破解成功: {hit.group(1).strip()}"]
            head.append("下一步：立即验证该密码是否在目标其他系统/SSID 上复用。")
        else:
            head = ["未破解成功（字典未命中）。建议：换更大字典 / 用 hashcat+GPU / 检查是否真是 WPA 握手包。"]
        return self._summary(raw, head, tail=40)
