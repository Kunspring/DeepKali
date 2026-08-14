"""ldapsearch 深度定制：LDAP 目录枚举（域渗透信息收集）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ldap_enum",
            "description": (
                "用 ldapsearch 枚举 LDAP/AD 目录信息。"
                "域渗透侦察：匿名查询或带凭据查询用户、组、计算机、域策略。"
                "典型过滤器：'(objectClass=user)' 枚举用户、'(objectClass=computer)' 枚举主机。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "LDAP 服务器 IP/域名（389 端口）"},
                    "base_dn": {
                        "type": "string",
                        "description": "搜索基 DN，如 'DC=corp,DC=local'（默认根）",
                    },
                    "filter": {
                        "type": "string",
                        "description": "LDAP 过滤器，默认 '(objectClass=*)'",
                    },
                    "attributes": {
                        "type": "string",
                        "description": "要返回的属性（空格分隔），如 'sAMAccountName memberOf'",
                    },
                    "username": {"type": "string", "description": "绑定用户（可选，默认匿名）"},
                    "password": {"type": "string", "description": "密码（配合 username）"},
                    "limit": {
                        "type": "integer",
                        "description": "最多返回条目数（默认 200）",
                    },
                },
                "required": ["host"],
            },
        },
    },
]

_DN_RE = re.compile(r"^[A-Za-z0-9=,.\- ]{1,256}$")
_FILTER_RE = re.compile(r"^[A-Za-z0-9=()&|!*.,'\- ]{1,300}$")
_ATTR_RE = re.compile(r"^[A-Za-z0-9_\- ]{1,200}$")
_CRED_RE = re.compile(r"^[\w.\-\\$]{1,64}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    host = sanitize_target(str(args["host"]))
    base_dn = str(args.get("base_dn") or "").strip()
    if base_dn and not _DN_RE.match(base_dn):
        raise ValueError(f"base_dn 含非法字符: {base_dn!r}")
    filt = str(args.get("filter") or "(objectClass=*)").strip()
    if not _FILTER_RE.match(filt):
        raise ValueError(f"filter 含非法字符: {filt!r}")
    attrs = str(args.get("attributes") or "").strip()
    if attrs and not _ATTR_RE.match(attrs):
        raise ValueError(f"attributes 含非法字符: {attrs!r}")
    username = str(args.get("username") or "").strip()
    password = str(args.get("password") or "").strip()
    for v, label in ((username, "username"), (password, "password")):
        if v and not _CRED_RE.match(v):
            raise ValueError(f"{label} 含非法字符: {v!r}")

    parts = ["ldapsearch", "-x", "-H", f"ldap://{host}"]
    if username:
        parts += ["-D", f"{username}", "-w", password or ""]
    if base_dn:
        parts += ["-b", base_dn]
    parts += ["-s", "sub", "-LLL"]
    if attrs:
        parts += ["-z", "200", filt, *attrs.split()]
    else:
        parts += ["-z", "200", filt]
    return " ".join(parts), 120


def _summarize(raw: str) -> str:
    dns = [
        l.strip().removeprefix("dn: ")
        for l in raw.splitlines()
        if l.startswith("dn: ")
    ]
    head: list[str] = []
    if dns:
        head.append(f"LDAP 条目 ({len(dns)}):")
        head += dns[:30]
        if len(dns) > 30:
            head.append(f"… 共 {len(dns)} 条")
        head.append("下一步建议：提取 sAMAccountName/CN 用于口令测试或进一步查询。")
    else:
        head = ["无结果（基 DN 可能不对、匿名被拒或过滤器无匹配）"]
    return ToolProfile._summary(raw, head, tail=40)


class LdapsearchProfile(ToolProfile):
    name = "ldapsearch"
    aliases = ["ldap 枚举", "ldapsearch", "域枚举", "ad 查询", "活动目录"]
    summary = "LDAP/AD 目录枚举"
    lore = """### ldapsearch 深度使用要点
- 定位：nmap 发现 389/tcp (ldap) 或 636 (ldaps) 后使用；域内 DC 几乎必开。
- 常用过滤器：`(objectClass=user)` 用户、`(objectClass=computer)` 主机、`(objectClass=group)` 组、
  `(sAMAccountName=administrator)` 精确查、`(&(objectClass=user)(memberOf=CN=Domain Admins,...))` 查高权限组。
- 属性：sAMAccountName（登录名）、memberOf（所属组）、userAccountControl（禁用/锁定标志）、description（常有密码注释！）。
- 匿名被拒时用拿到的一组凭据绑定（-D domain\\user -w pass）。
- 大域查询加 -z 限制条目数（已内置 200），防止输出爆炸。"""
    extra_schemas = SCHEMAS

    async def exec_ldap_enum(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("ldapsearch"):
            return "ldapsearch 未安装（apt install ldap-utils）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
