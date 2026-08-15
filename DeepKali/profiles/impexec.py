"""impacket 远程执行深度定制：smbexec / wmiexec / atexec 三合一（危险操作）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

MODES = {
    "smbexec": "SMB 服务执行（动静最小，默认）",
    "wmiexec": "WMI 执行（不走 SMB 服务）",
    "atexec": "计划任务执行（需要管理员权限）",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "imp_exec",
            "description": (
                "用 impacket（smbexec/wmiexec/atexec）在 Windows 主机上非交互执行命令。"
                "⚠ 危险操作：会触发确认弹窗；横向移动核心工具，凭据来自破解/secretsdump。"
                "三种方式互补：smbexec 动静最小、wmiexec 不依赖 SMB 服务、atexec 需管理员。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标 Windows 主机 IP"},
                    "username": {"type": "string", "description": "用户名（支持 domain\\user）"},
                    "password": {"type": "string", "description": "明文密码（与 hash 二选一）"},
                    "hash": {
                        "type": "string",
                        "description": "NTLM hash（Pass-the-Hash）",
                    },
                    "mode": {
                        "type": "string",
                        "enum": list(MODES),
                        "description": "执行方式（默认 smbexec）",
                    },
                    "command": {
                        "type": "string",
                        "description": "要执行的命令（默认 whoami），如 'ipconfig' 或 'net user'",
                    },
                    "domain": {"type": "string", "description": "域名（可选）"},
                },
                "required": ["host", "username"],
            },
        },
    },
]

_USER_RE = re.compile(r"^[\w.\-\\$]{1,64}$")
_PASS_RE = re.compile(r"^[\w.\-\\$@!]{1,128}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_CMD_RE = re.compile(r"^[\w\s./:,-]{1,200}$")


def _bin(mode: str) -> str:
    names = {
        "smbexec": ("impacket-smbexec", "smbexec.py"),
        "wmiexec": ("impacket-wmiexec", "wmiexec.py"),
        "atexec": ("impacket-atexec", "atexec.py"),
    }[mode]
    for n in names:
        if check_installed(n):
            return n
    return ""


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    username = str(args.get("username") or "").strip()
    if not _USER_RE.match(username):
        raise ValueError(f"username 格式非法: {username!r}")
    password = str(args.get("password") or "").strip()
    hashv = str(args.get("hash") or "").strip()
    if bool(password) == bool(hashv):
        raise ValueError("password 与 hash 必须且只能提供一个")
    if hashv and not _HASH_RE.match(hashv):
        raise ValueError("hash 必须是 32 位 NTLM hash")
    mode = str(args.get("mode") or "smbexec").strip().lower()
    if mode not in MODES:
        raise ValueError(f"mode 仅支持: {', '.join(MODES)}")
    command = str(args.get("command") or "whoami").strip()
    if not _CMD_RE.match(command):
        raise ValueError(f"command 含非法字符: {command!r}")
    domain = str(args.get("domain") or "").strip()
    if domain and not _USER_RE.match(domain):
        raise ValueError(f"domain 格式非法: {domain!r}")

    bin_ = _bin(mode)
    if not bin_:
        return "", 0
    prefix = f"{domain}\\" if domain else ""
    if password:
        conn = f"{prefix}{username}:{password}@{host}"
    else:
        conn = f"{prefix}{username}@{host}"
    extra = f"-hashes :{hashv}" if hashv else ""
    return f"{bin_} {extra} {conn} {command}".strip(), 120


class ImpExecProfile(ToolProfile):
    name = "impexec"
    aliases = ["smbexec", "wmiexec", "atexec", "横向执行", "远程执行命令", "psexec"]
    summary = "impacket 远程命令执行"
    lore = """### impacket 远程执行深度使用要点
- 定位：横向移动核心——拿到凭据后在多台 Windows 主机执行命令/部署工具。
- 选型：smbexec 走 SMB 服务动静最小；wmiexec 不依赖 SMB 服务（445 被防火墙限制时用）；atexec 用计划任务需管理员。
- Pass-the-Hash：-hashes :<NTLM hash> 直接登录（与 secretsdump 提取的 hash 配合）。
- 常见命令：whoami / ipconfig / net user / net localgroup administrators / tasklist。
- 大动作（下载工具、开 RDP、部署后门）前先确认授权；命令输出是标准 cmd 输出。"""
    extra_schemas = SCHEMAS

    async def exec_imp_exec(self, ex: Any, args: dict[str, Any]) -> str:
        if not _bin(str(args.get("mode") or "smbexec")):
            return "impacket 执行工具未安装（apt install python3-impacket）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        # 去 banner 行（impacket 输出头）
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        body = [l for l in lines if not l.startswith(("Impacket", "[!", "[*]"))]
        head = body[:25] if body else ["命令执行完成但无输出（检查凭据/权限）"]
        return self._summary(raw, head, tail=40)
