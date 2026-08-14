"""evil-winrm 深度定制：WinRM 远程命令执行（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_int, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "winrm_exec",
            "description": (
                "通过 WinRM（5985/5986）在 Windows 主机上远程执行单条命令（evil-winrm）。"
                "⚠ 危险操作：会触发确认弹窗。凭据可来自 hydra 破解或 hash（Pass-the-Hash）。"
                "执行后建议继续侦察（whoami/ipconfig）或横向。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Windows 主机 IP/主机名"},
                    "username": {"type": "string", "description": "用户名（如 administrator）"},
                    "password": {
                        "type": "string",
                        "description": "明文密码（与 hash 二选一）",
                    },
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash（Pass-the-Hash，与 password 二选一）",
                    },
                    "port": {
                        "type": "integer",
                        "description": "WinRM 端口（默认 5985；HTTPS 用 5986）",
                    },
                    "command": {
                        "type": "string",
                        "description": "要执行的命令（默认 whoami）",
                    },
                },
                "required": ["host", "username"],
            },
        },
    },
]

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_CMD_RE = re.compile(r"^[\w\s./:,-]{1,200}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    username = str(args.get("username") or "").strip()
    if not re.fullmatch(r"[\w.\-\\$]{1,64}", username):
        raise ValueError(f"username 格式非法: {username!r}")
    password = str(args.get("password") or "").strip()
    hashv = str(args.get("hash") or "").strip()
    if bool(password) == bool(hashv):
        raise ValueError("password 与 hash 必须且只能提供一个")
    if hashv and not _HASH_RE.match(hashv):
        raise ValueError("hash 必须是 32 位 NTLM hash")
    port = sanitize_int(args.get("port"), 5985, 1, 65535, "port", strict=True)
    command = str(args.get("command") or "whoami").strip()
    if not _CMD_RE.match(command):
        raise ValueError(f"command 含非法字符: {command!r}")

    parts = ["evil-winrm", "-i", host, "-u", username, "-P", str(port)]
    if password:
        parts += ["-p", password]
    else:
        parts += ["-H", hashv]
    parts += ["-c", command]
    return " ".join(parts), 120


class EvilWinrmProfile(ToolProfile):
    name = "evil-winrm"
    aliases = ["winrm", "windows 远程", "pth", "pass the hash"]
    summary = "WinRM 远程命令执行"
    lore = """### evil-winrm 深度使用要点
- 前置：nmap 发现 5985/tcp (http) 或 5986 (https) 开放；凭据来自破解/横向。
- Pass-the-Hash：拿到 NTLM hash 后无需明文密码，-H 直接登录。
- 权限判断：whoami → 是否 administrator；域环境先 `whoami /all` 看特权。
- 获得管理员后：抓 LSASS 内存（sekurlsa）或直接开 RDP/计划任务做持久化（先确认授权）。
- 一次执行一条命令（-c）；交互 shell 更适合单独开一个终端让用户操作。"""
    extra_schemas = SCHEMAS

    async def exec_winrm_exec(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("evil-winrm"):
            return "evil-winrm 未安装（apt install evil-winrm）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        # 去掉 evil-winrm 的 banner（Evil-WinRM shell v3.x）
        body = [l for l in lines if not l.startswith(("Evil-WinRM", "Info:", "*", "PS "))]
        head = body[:25] if body else lines[:25]
        return self._summary(raw, head, tail=40)
