"""smbclient 深度定制：SMB 共享目录浏览与文件操作（非交互 -c 封装）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

# 允许的 -c 命令（防任意命令注入）
_ALLOWED_CMDS = ("ls", "recurse", "allinfo", "dir", "pwd", "du")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "smb_ls",
            "description": (
                "用 smbclient 非交互浏览 SMB 共享目录（默认匿名，可带凭据）。"
                "与 smb_map 互补：smb_map 看共享总览，smb_ls 看某个共享的具体目录/文件权限。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标 IP/主机名"},
                    "share": {"type": "string", "description": "共享名，如 'C$' 或 'shared'"},
                    "path": {
                        "type": "string",
                        "description": "共享内路径（可选），如 'Users/Public'",
                    },
                    "username": {"type": "string", "description": "用户名（默认匿名）"},
                    "password": {"type": "string", "description": "密码"},
                    "domain": {"type": "string", "description": "域（可选）"},
                },
                "required": ["host", "share"],
            },
        },
    },
]

_SHARE_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")  # 允许 C$ / ADMIN$
_PATH_RE = re.compile(r"^[\w./\\ -]{0,200}$")
_VALUE_RE = re.compile(r"^[\w.\-\\$]{1,64}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    share = str(args.get("share") or "").strip()
    if not _SHARE_RE.match(share):
        raise ValueError(f"share 格式非法: {share!r}")
    path = str(args.get("path") or "").strip()
    if path and not _PATH_RE.match(path):
        raise ValueError(f"path 含非法字符: {path!r}")
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    domain = str(args.get("domain") or "").strip()
    for v, label in ((username, "username"), (domain, "domain")):
        if v and not _VALUE_RE.match(v):
            raise ValueError(f"{label} 含非法字符: {v!r}")

    target = f"//{host}/{share}"
    if path:
        target += f"/{path}"

    if username:
        # 域\用户 用单引号包裹：反斜杠在 bash 里可能是转义（\a 是 BEL）
        cred = f"-U '{domain + '\\' if domain else ''}{username}%{password or ''}'"
        parts = ["smbclient", target, cred]
    elif domain:
        parts = ["smbclient", target, "-W", domain]
    else:
        parts = ["smbclient", target, "-N"]
    parts += ["-c", "ls"]
    return " ".join(parts), 120


def _summarize(raw: str) -> str:
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    # 文件行: 名字 大小 类型 时间 或 "D" 开头目录
    entries = [
        l
        for l in lines
        if re.match(r"^[A-Za-z0-9_.$ -]+\s+(D|A|N|RHS)", l) or l.startswith("D ")
    ]
    denied = any("NT_STATUS" in l for l in lines)
    head: list[str] = []
    if entries:
        head.append(f"目录内容 ({len(entries)} 项):")
        head += entries[:40]
    if denied:
        head.append("⚠ 访问被拒（NT_STATUS_ACCESS_DENIED）——可尝试其他凭据或共享。")
    if not head:
        head = ["无法列出目录（共享不存在/无权限/未连接）"]
    return ToolProfile._summary(raw, head, tail=40)


class SmbclientProfile(ToolProfile):
    name = "smbclient"
    aliases = ["smb 目录", "smbclient", "共享浏览", "查看共享", "共享目录"]
    summary = "SMB 共享目录浏览"
    lore = """### smbclient 深度使用要点
- 定位：smb_map 发现共享后，用它看具体目录结构；支持 C$/ADMIN$ 管理共享（需管理员凭据）。
- 匿名优先：很多机器 IPC$ 可匿名列目录；有凭据后看用户目录（Users/<name>/Desktop 等）。
- 关注文件：密码本、配置文件、备份（.bak/.zip）、下载目录——横向移动的凭据来源。
- 交互式更灵活（上传/下载/删除），需要时可提示用户进入 smbclient 交互 shell。
- NT_STATUS_ACCESS_DENIED 说明缺权限，换凭据或换共享。"""
    extra_schemas = SCHEMAS

    async def exec_smb_ls(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("smbclient"):
            return "smbclient 未安装（apt install smbclient）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
