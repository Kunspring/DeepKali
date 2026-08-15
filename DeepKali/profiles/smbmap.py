"""smbmap 深度定制：SMB 共享枚举与文件浏览。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "smb_map",
            "description": (
                "枚举/浏览 SMB 共享（smbmap）：列出所有共享，或递归列出某个共享的文件。"
                "默认匿名（null session）；也可带凭据。与 smb_enum 配合：先找共享，再看内容。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标 IP/主机名"},
                    "username": {"type": "string", "description": "用户名（默认匿名）"},
                    "password": {"type": "string", "description": "密码"},
                    "domain": {"type": "string", "description": "域（可选）"},
                    "share": {"type": "string", "description": "指定共享名（默认列出所有共享）"},
                    "recursive": {
                        "type": "boolean",
                        "description": "递归列出共享内文件（默认 false，只列根目录）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_VALUE_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")  # 允许 C$ / ADMIN$ 等共享名


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = sanitize_target(str(args["target"]))
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    domain = str(args.get("domain") or "").strip()
    share = str(args.get("share") or "").strip()
    recursive = bool(args.get("recursive"))
    for v, label in ((username, "username"), (password, "password"), (domain, "domain"), (share, "share")):
        if v and not _VALUE_RE.match(v):
            raise ValueError(f"{label} 含非法字符: {v!r}")

    parts = ["smbmap", "-H", target]
    if username:
        parts += ["-u", username]
        parts += ["-p", password or ""]  # 空密码也显式传
    if domain:
        parts += ["-d", domain]
    if share:
        parts += ["-s", share]
    if recursive:
        parts.append("-R")
    return " ".join(parts), 120


def _summarize(raw: str) -> str:
    shares = [
        l.strip()
        for l in raw.splitlines()
        if re.match(r"^\s*(Disk|IPC|Printer)\s+", l) or re.match(r"^\s*\S+\s+READ", l)
    ]
    files = [l.strip() for l in raw.splitlines() if re.match(r"^\S+\s+[A-Z]+\s+", l) and "/" in l]
    head: list[str] = []
    if shares:
        head.append("共享列表:")
        head += shares[:20]
    if files:
        head.append("共享内文件（前 30）:")
        head += files[:30]
    if not head:
        head = ["未列出共享（可能匿名访问被拒）。可尝试 smb_enum 或提供凭据。"]
    return ToolProfile._summary(raw, head, tail=40)


class SmbmapProfile(ToolProfile):
    name = "smbmap"
    aliases = ["smb 共享", "共享文件", "smb 浏览"]
    summary = "SMB 共享枚举与文件浏览"
    lore = """### smbmap 深度使用要点
- 定位：smb_enum 找到共享后，用它查看共享内容；默认匿名尝试（很多内网机器 IPC$/共享可匿名读）。
- 递归 -R 列出文件；关注敏感文件：配置文件、备份、密码文件（.conf/.bak/.txt/.xlsx）。
- 有凭据时用 -u/-p/-d 指定；拿到用户列表后可尝试弱口令组合。
- 发现可写共享（WRITE 权限）是突破口：可考虑上传 webshell/计划任务（需先确认授权）。"""
    extra_schemas = SCHEMAS

    async def exec_smb_map(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("smbmap"):
            return "smbmap 未安装（apt install smbmap）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
