"""theHarvester 深度定制：OSINT 子域/邮箱/主机收集。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed

SOURCES = (
    "all", "baidu", "bing", "crtsh", "dnsdumpster", "google", "hackertarget",
    "otx", "rapiddns", "sublist3r", "virustotal", "yahoo",
)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "osint_gather",
            "description": (
                "用 theHarvester 从公开源（证书透明日志、搜索引擎等）收集目标的子域、邮箱、主机。"
                "外网侦察：不需要接触目标服务器，纯被动收集。"
                "收集到的子域/邮箱是后续定向攻击的入口清单。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "目标域名，如 example.com"},
                    "source": {
                        "type": "string",
                        "enum": list(SOURCES),
                        "description": "数据源（默认 crtsh 证书透明日志，最快最全）",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "结果上限（默认 100）",
                    },
                },
                "required": ["domain"],
            },
        },
    },
]


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    domain = str(args["domain"]).strip()
    if not re.fullmatch(r"[\w.-]{1,128}", domain):
        raise ValueError(f"domain 格式非法: {domain!r}")
    source = str(args.get("source") or "crtsh").strip().lower()
    if source not in SOURCES:
        raise ValueError(f"source 仅支持: {', '.join(SOURCES[:8])} …")
    try:
        limit = int(args.get("limit", 100))
        if not 10 <= limit <= 500:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"limit 必须在 10-500: {args.get('limit')!r}")
    return f"theHarvester -d {domain} -b {source} -l {limit}", 180


def _summarize(raw: str) -> str:
    hosts: list[str] = []
    for l in raw.splitlines():
        l = l.strip()
        # 两种格式：裸子域 / 子域:IP（hackertarget 等源）
        m = re.match(r"^([\w.-]+\.[a-z]{2,})(:\d{1,3}(\.\d{1,3}){3})?$", l, re.IGNORECASE)
        if m:
            hosts.append(m.group(1))
    emails = [l.strip() for l in raw.splitlines() if re.match(r"^[\w.+-]+@[\w.-]+\.[a-z]{2,}$", l, re.IGNORECASE)]
    hosts = sorted(set(hosts))
    emails = sorted(set(emails))
    head: list[str] = []
    if hosts:
        head.append(f"子域/主机 ({len(hosts)}):")
        head += hosts[:30]
        if len(hosts) > 30:
            head.append(f"… 共 {len(hosts)} 个")
    if emails:
        head.append(f"邮箱 ({len(emails)}):")
        head += emails[:20]
    if not head:
        head = ["未收集到结果（数据源无记录或网络受限）"]
    head.append("下一步建议：对子域逐一 nmap；邮箱列表可用于钓鱼评估或用户名枚举。")
    return ToolProfile._summary(raw, head, tail=40)


class TheHarvesterProfile(ToolProfile):
    name = "theharvester"
    aliases = ["osint", "子域收集", "邮箱收集", "theharvester", "公开情报", "子域", "邮箱", "收集"]
    summary = "OSINT 子域/邮箱收集"
    lore = """### theHarvester 深度使用要点
- 定位：外网侦察第一阶段——纯被动收集，不接触目标服务器。
- 数据源选择：crtsh（证书透明日志）最快最全；hackertarget/otx 补充；google/bing 慢且可能被验证码。
- 输出分 Hosts/Emails 两段：子域直接 nmap 跟进；邮箱验证存在性后可用于钓鱼/撞库评估。
- 与 dns_recon 互补：theHarvester 找子域 → dns_recon 查子域记录 → nmap 扫服务。
- 反制意识：收集到的信息可能包含蜜罐/CDN 节点，先用 DNS 解析确认。"""
    extra_schemas = SCHEMAS

    async def exec_osint_gather(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("theHarvester"):
            return "theHarvester 未安装（apt install theharvester）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
