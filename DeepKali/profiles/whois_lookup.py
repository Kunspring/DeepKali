"""Whois 查询：提取域名/IP 的注册信息关键字段（注册商/时间/DNS/注册人）。

白帽定位：侦察第一步——whois 拿注册商、注册/过期时间、DNS 服务器、
注册人组织/国家；关联同一注册人的其他资产（扩展攻击面）、发现过期
域名（接管理）、注册邮箱（社工面）。Kali 自带 whois。
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "whois_lookup",
            "description": (
                "Whois 查询：提取域名/IP 的注册商、注册/过期时间、DNS 服务器、"
                "注册人组织与国家等关键字段（OSINT 侦察第一步）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "域名或 IP，如 example.com",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

# (字段名, 匹配关键字列表) —— 按优先级取第一个命中
_FIELDS: list[tuple[str, tuple[str, ...]]] = [
    ("注册商", ("registrar:", "sponsoring registrar", "registrar name")),
    ("创建时间", ("creation date:", "created:", "registered on", "created on")),
    ("过期时间", ("registry expiry date:", "expiry date:", "expires:", "registry expiration")),
    ("更新时间", ("updated date:", "last updated:", "updated on")),
    ("DNS 服务器", ("name server:", "nameserver:", "nserver:")),
    ("注册人组织", ("registrant organization:", "registrant org:", "org-name:")),
    ("注册人国家", ("registrant country:", "country:")),
    ("注册邮箱", ("registrant email:", "registrant e-mail:", "e-mail:")),
]


def _build_cmd(target: str) -> str:
    return f"whois {target}"


def _parse(raw: str) -> dict[str, str]:
    """提取关键字段（按关键字前缀匹配，大小写不敏感）。"""
    out: dict[str, str] = {}
    for label, keys in _FIELDS:
        for line in raw.splitlines():
            low = line.strip().lower()
            for k in keys:
                if low.startswith(k):
                    val = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
                    if val:
                        out[label] = val[:200]
                    break
            if label in out:
                break
    return out


def _summarize(raw: str, target: str) -> str:
    info = _parse(raw)
    head: list[str] = [f"🌐 {target} whois 摘要:"]
    if info:
        for label, val in info.items():
            head.append(f"  {label}: {val}")
    else:
        head.append("  （未提取到标准字段——可能无记录或 whois 服务器无应答）")
    head.append("下一步：用注册邮箱/组织名反查关联资产（theharvester/gau）；"
                "过期域名注意续费接管风险；DNS 服务器变化排查劫持。")
    return ToolProfile._summary(raw, head, tail=25)


class WhoisLookupProfile(ToolProfile):
    name = "whois_lookup"
    aliases = ["whois 查询", "域名信息", "注册信息", "whois", "域名归属", "注册商查询"]
    summary = "Whois 注册信息查询"
    lore = """### whois 查询使用要点
- 定位：侦察第一步——注册商/注册时间/DNS 服务器/注册人组织国家，快速建立目标画像。
- 扩展面：同一注册邮箱/组织名查其他域名（theharvester 或 whois 反查服务）；
  过期时间近的域名注意续费接管；DNS 服务器归属（如用第三方托管）是后续攻击面。
- 反查技巧：注册人邮箱前缀常是姓氏拼音（zhangsan@xxx）→ 可扩展用户枚举。
- 隐私保护（whois privacy）下注册人字段被隐藏属正常，不代表无风险。
- 注意：whois 输出格式因 TLD/注册商差异大（RIR/Verisign/各国），字段匹配失败时
  看原始输出手工判断。"""
    extra_schemas = SCHEMAS

    async def exec_whois_lookup(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("whois"):
            return "whois 未安装（apt install whois）。"
        target = str(args.get("target") or "").strip().lower()
        if not (_DOMAIN_RE.match(target) and "." in target) and not _IP_RE.match(target):
            return f"target 格式非法（应为域名或 IP）: {target!r}"
        raw = await self._run(ex, _build_cmd(target), timeout=30)
        return _summarize(raw, target)
