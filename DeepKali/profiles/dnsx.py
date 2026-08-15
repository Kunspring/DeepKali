"""dnsx：批量 DNS 解析（子域存活验证/A 记录查询，subfinder 后置过滤）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "dnsx",
            "description": (
                "用 dnsx 批量解析域名（A/CNAME 记录查询、子域存活验证）。"
                "subfinder 枚举出大量子域后，用它过滤掉不解析的死域/CDN 泛解析，"
                "得到真实可达的资产列表再交给 httpx 探活。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "string",
                        "description": "域名列表：逗号分隔（如 api.example.com,www.example.com）",
                    },
                    "resolve": {
                        "type": "boolean",
                        "description": "输出解析到的 IP（默认 true）",
                    },
                },
                "required": ["domains"],
            },
        },
    },
]

_DOMAIN_RE = re.compile(r"^[\w.-]{1,128}$")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _build_cmd(domains: list[str], resolve: bool) -> str:
    parts = ["dnsx"]
    if resolve:
        parts.append("-a")
    parts += ["-silent", "-d"]
    parts += domains
    return " ".join(parts), 120


def _summarize(raw: str) -> str:
    pairs: list[tuple[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[" in line and "]" in line:  # dnsx -a 输出：domain [ip, ip]
            m = re.match(r"([\w.-]+)\s*\[([^\]]*)\]", line)
            if m:
                pairs.append((m.group(1), m.group(2)))
        elif _IP_RE.search(line):
            parts = line.split()
            pairs.append((parts[0], parts[1] if len(parts) > 1 else ""))
        elif _DOMAIN_RE.match(line):
            # resolve=False 纯域名输出 → 解析成功但无 A 记录信息
            pairs.append((line, ""))
    if not pairs:
        return ToolProfile._summary(raw, ["无域名解析成功（全部死域/暂不可解析）"], tail=15)
    head = [
        f"🎯 解析成功 {len(pairs)}/{len(pairs)} 个域名:",
    ]
    for domain, ip in pairs[:30]:
        head.append(f"  {domain} → {ip or '（无 A 记录）'}")
    if len(pairs) > 30:
        head.append(f"  …等 {len(pairs)} 个")
    head.append("下一步：httpx 对解析成功的域名探活+指纹 → whatweb → 专项深入。")
    return ToolProfile._summary(raw, head, tail=10)


class DnsxProfile(ToolProfile):
    name = "dnsx"
    aliases = ["dns 解析", "dnsx", "批量解析", "子域验证", "域名解析"]
    summary = "批量 DNS 解析验证"
    lore = """### dnsx 深度使用要点
- 定位：subfinder 的"过滤器"。枚举出的子域里有大量不解析的域名、
  CDN/泛解析（*.example.com 全返回同一 IP）、已下线的旧子域——
  dnsx -a 一次全部解析，过滤后只剩真实资产。
- 用法：`dnsx -a -silent -d api.example.com www.example.com`；
  批量时把 subfinder 输出管道进来（subfinder -d x -silent | dnsx -a）。
- 泛解析识别：大量子域解析到同一 IP 且非 CDN 段 → 泛解析，价值低；
  CDN（Cloudflare 等）IP 段单独标注，扫描时走 CDN 绕过思路。
- 联动：subfinder → dnsx（过滤）→ httpx（探活+状态码）→
  whatweb（指纹）→ nuclei（批量模板）。"""
    extra_schemas = SCHEMAS

    async def exec_dnsx(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("dnsx"):
            return "dnsx 未安装（go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest）。"
        raw_domains = str(args.get("domains") or "").strip()
        domains = [d.strip() for d in raw_domains.split(",") if d.strip()]
        if not domains:
            raise ValueError("domains 不能为空")
        if len(domains) > 200:
            raise ValueError(f"domains 过多（{len(domains)} 个，上限 200）")
        for d in domains:
            if not _DOMAIN_RE.match(d):
                raise ValueError(f"域名格式非法: {d!r}")
        resolve = bool(args.get("resolve", True))
        raw = await self._run(ex, *_build_cmd(domains, resolve))
        return _summarize(raw)
