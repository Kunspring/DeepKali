"""dnsrecon 深度定制：DNS 侦察（标准查询 / 子域爆破 / 区域传送）。"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_target,
    sanitize_wordlist,
)

MODES = {
    "std": "标准查询：A/AAAA/CNAME/MX/NS/SOA/TXT/SRV（默认）",
    "brt": "子域爆破（需字典）",
    "axfr": "尝试 DNS 区域传送（信息泄露漏洞）",
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "dns_recon",
            "description": (
                "对域名做 DNS 侦察（dnsrecon）：枚举记录、爆破子域、测试区域传送。"
                "外网信息收集阶段使用；axfr 若成功说明 DNS 配置存在区域传送漏洞。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标域名，如 example.com"},
                    "mode": {
                        "type": "string",
                        "enum": list(MODES),
                        "description": "侦察模式（默认 std）",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "子域字典（brt 模式用，默认 /usr/share/wordlists/dnsrecon/subdomains-top1million-20000.txt）",
                    },
                    "server": {
                        "type": "string",
                        "description": "指定 DNS 服务器（可选）",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

_SERVER_RE = re.compile(r"^[\w.-]{1,255}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = sanitize_target(str(args["target"]), label="域名")
    mode = str(args.get("mode") or "std").strip().lower()
    if mode not in MODES:
        raise ValueError(f"mode 仅支持: {', '.join(MODES)}")
    server = str(args.get("server") or "").strip()
    if server and not _SERVER_RE.match(server):
        raise ValueError("server 格式非法")

    parts = ["dnsrecon", "-d", target]
    if mode == "std":
        parts.append("-t std")
    elif mode == "brt":
        wl = (
            sanitize_wordlist(str(args.get("wordlist") or ""))
            if args.get("wordlist")
            else "/usr/share/wordlists/dnsrecon/subdomains-top1million-20000.txt"
        )
        parts += ["-t brt", "-D", wl]
    else:
        parts.append("-t axfr")
    if server:
        parts += ["-n", server]
    return " ".join(parts), 300


def _summarize(raw: str) -> str:
    # 兼容新旧两种格式:
    #   旧版: [A] example.com 1.2.3.4
    #   新版: 2026-08-14T21:57:11.8 INFO \t A example.com 1.2.3.4
    records = []
    for l in raw.splitlines():
        l = l.strip()
        if any(x in l for x in ("Bind Version", "Enumerating", "Completed", "Recursion", "Wildcard")):
            continue
        m = re.search(r"INFO\s+(\w+)\s+(\S+.*)$", l)
        if m and m.group(1) in ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "PTR"):
            records.append(f"[{m.group(1)}] {m.group(2)}")
        elif re.match(r"^\[(A|AAAA|CNAME|MX|NS|SOA|TXT|SRV|PTR)\]", l):
            records.append(l)
    # 去重保序：同一类型+记录名只保留一条（SOA/NS 常有多条冗余）
    seen: set[str] = set()
    uniq: list[str] = []
    for r in records:
        key = re.sub(r"\s+\S+$", "", r)  # 去掉末尾值，按 类型+名称 去重
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    axfr_ok = any("Zone Transfer" in l and "successful" in l.lower() for l in raw.splitlines())
    head: list[str] = []
    if uniq:
        head.append(f"解析记录 ({len(uniq)}):")
        head += uniq[:40]
        if len(uniq) > 40:
            head.append(f"… 共 {len(uniq)} 条")
    if axfr_ok:
        head.append("🎯 区域传送成功！DNS 配置存在漏洞，可获取完整域名信息。")
    if not head:
        head = ["未发现解析记录（域名可能无记录或查询被拒）"]
    return ToolProfile._summary(raw, head, tail=40)


class DnsreconProfile(ToolProfile):
    name = "dnsrecon"
    aliases = ["dns 侦察", "子域爆破", "区域传送", "域名枚举", "子域名"]
    summary = "DNS 信息侦察"
    lore = """### dnsrecon 深度使用要点
- 定位：拿到目标域名后第一步做 DNS 侦察；与 whois/证书透明度枚举互补。
- std 模式看 MX/NS/子域记录：NS 记录透露 DNS 服务器，可尝试 axfr 区域传送。
- brt 子域爆破用大字典更全（subdomains-top1million 系列在 /usr/share/wordlists/dnsrecon/）。
- 发现的子域名（如 vpn/dev/staging）往往是内网入口或未加固系统，逐一 nmap 跟进。
- axfr 成功 = 配置漏洞，记录全部记录并汇报。"""
    extra_schemas = SCHEMAS

    async def exec_dns_recon(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("dnsrecon"):
            return "dnsrecon 未安装（apt install dnsrecon）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
