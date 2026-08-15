"""enum4linux 深度定制：SMB/NetBIOS 枚举（用户、共享、组、密码策略）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

MODES = {
    "all": "全量枚举（-a）",
    "users": "用户枚举（-U）",
    "shares": "共享枚举（-S）",
    "groups": "组/本地组枚举（-G）",
    "policy": "密码策略（-P）",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "smb_enum",
            "description": (
                "对 SMB/NetBIOS 服务（445/139）做信息枚举（enum4linux）。"
                "内网渗透第一步：找用户、共享、组、密码策略，为后续口令测试/共享访问铺路。"
                "nmap 发现 445 开放后使用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 IP/主机名"},
                    "mode": {
                        "type": "string",
                        "enum": list(MODES),
                        "description": "枚举范围（默认 all 全量）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = sanitize_target(str(args["target"]))
    mode = str(args.get("mode") or "all").strip().lower()
    if mode not in MODES:
        raise ValueError(f"mode 仅支持: {', '.join(MODES)}")
    flags = {
        "all": "-a",
        "users": "-U",
        "shares": "-S",
        "groups": "-G",
        "policy": "-P",
    }[mode]
    return f"enum4linux {flags} {target}", 180


def _summarize(raw: str) -> str:
    def _field(line: str) -> str:
        _, _, v = line.partition(":")
        return v.strip() or line.replace("[+]", "", 1).strip()

    pos = [l.strip() for l in raw.splitlines() if l.startswith("[+]")]
    users = [
        _field(l)
        for l in pos
        if re.search(r"user:|Local User|users:", l, re.IGNORECASE)
    ]
    shares = [
        _field(l)
        for l in pos
        if re.search(r"Sharename|share:", l, re.IGNORECASE) and "Sharename" not in l
    ]
    groups = [
        _field(l)
        for l in pos
        if re.search(r"Group:|group:", l, re.IGNORECASE)
    ]
    head: list[str] = []
    if users:
        head.append(f"👤 枚举到用户 ({len(users)}): " + ", ".join(users[:20]))
    if shares:
        head.append(f"📁 共享 ({len(shares)}): " + ", ".join(shares[:20]))
    if groups:
        head.append(f"👥 组 ({len(groups)}): " + ", ".join(groups[:10]))
    if not head:
        head = ["未枚举到明显信息（可能 SMB 未开放或拒绝匿名访问）"]
    head.append("下一步建议：用户名单可用于 hydra 弱口令；共享可用 smb_map 查看内容。")
    return ToolProfile._summary(raw, head, tail=40)


class Enum4linuxProfile(ToolProfile):
    name = "enum4linux"
    aliases = ["smb 枚举", "445 枚举", "共享枚举", "用户枚举", "netbios"]
    summary = "SMB/NetBIOS 信息枚举"
    lore = """### enum4linux 深度使用要点
- 定位：nmap 发现 445/tcp (microsoft-ds) 或 139 (netbios-ssn) 后使用。
- `all` 模式最全：用户、共享、组、密码策略一次拿齐；只想要某类用对应 mode。
- 关注 [+] 行：SID 枚举出的用户名是后续 hydra 弱口令的用户名单。
- 密码策略（-P）信息很有价值：锁定阈值/密码最短长度决定爆破策略。
- 新版本可用 enum4linux-ng（python 实现，输出更友好），命令格式相同。"""
    extra_schemas = SCHEMAS

    async def exec_smb_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("enum4linux"):
            return "enum4linux 未安装（apt install enum4linux）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
