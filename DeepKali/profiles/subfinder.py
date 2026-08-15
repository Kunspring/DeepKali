"""subfinder：子域名枚举（多数据源被动收集，SRC 资产发现第一步）。"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolProfile, check_installed, sanitize_target

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "subfinder",
            "description": (
                "用 subfinder 被动枚举目标域的子域名（证书透明/搜索引擎/DNS 数据源"
                "聚合，不直接爆破目标）。SRC 资产发现第一步：找到未被主站覆盖的"
                "子域往往就是突破口（旧系统/测试环境/管理后台）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "根域名，如 example.com",
                    },
                    "silent": {
                        "type": "boolean",
                        "description": "只输出子域名列表（默认 true，便于后续管道）",
                    },
                },
                "required": ["domain"],
            },
        },
    },
]

def _build_cmd(domain: str, silent: bool) -> str:
    parts = ["subfinder", "-d", domain]
    if silent:
        parts.append("-silent")
    return " ".join(parts), 240


def _summarize(raw: str, domain: str) -> str:
    subs: list[str] = []
    for line in raw.splitlines():
        line = line.strip().lower()
        if re.fullmatch(r"[\w*][\w.-]*\." + re.escape(domain), line):
            subs.append(line)
    subs = sorted(set(subs))
    if not subs:
        return ToolProfile._summary(raw, ["未发现子域名（数据源无结果/域名无效）"], tail=15)
    head = [
        f"🎯 发现 {len(subs)} 个子域名:",
        "  " + " ".join(subs[:40]),
        "下一步：httpx 探活+指纹 → whatweb 指纹 → 按指纹选 CMS/Web 专项；",
        "重点盯：测试环境（test/stage/dev）、管理后台（admin）、旧系统（v1/old）。",
    ]
    return ToolProfile._summary(raw, head, tail=10)


class SubfinderProfile(ToolProfile):
    name = "subfinder"
    aliases = ["子域名", "subfinder", "子域枚举", "资产发现", "域名枚举"]
    summary = "子域名被动枚举"
    lore = """### subfinder 深度使用要点
- 定位：SRC 资产发现第一步。被动聚合证书透明（crt.sh 等）、搜索引擎、
  DNS 数据源，不直接爆破——安静、合法、快。配合 crt.sh 工具互补。
- 用法：`subfinder -d example.com -silent` 只输出域名，方便管道给
  httpx/nuclei；加 `-all` 用全部数据源（更全更慢）。
- 后续链：subfinder → httpx -l subs.txt（探活+状态码+标题）→
  whatweb 指纹 → nuclei 批量模板。重点盯 test/stage/dev/admin/v1/old
  等子域——测试环境和旧系统是 SRC 突破口重灾区。
- 注意：被动枚举不产生直接攻击流量，但仍需在授权范围内使用；
  子域名可能是第三方托管（CDN/云服务），扫描前确认归属。"""
    extra_schemas = SCHEMAS

    async def exec_subfinder(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("subfinder"):
            return "subfinder 未安装（apt install subfinder 或 go install）。"
        domain = sanitize_target(str(args.get("domain") or ""))
        if not re.fullmatch(r"[\w.-]{1,128}", domain):  # pragma: no cover 防御双保险
            raise ValueError(f"domain 格式非法: {domain!r}")
        silent = bool(args.get("silent", True))
        raw = await self._run(ex, *_build_cmd(domain, silent))
        return _summarize(raw, domain)
