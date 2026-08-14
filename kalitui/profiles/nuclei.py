"""nuclei 深度定制：模板化漏洞扫描（危险操作，触发确认）。"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    ToolProfile,
    check_installed,
    sanitize_int,
    sanitize_target,
    sanitize_url,
)

SEVERITIES = ("info", "low", "medium", "high", "critical")

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nuclei_scan",
            "description": (
                "用 nuclei 对目标做模板化漏洞扫描（社区模板库，覆盖 CVE/配置/暴露面）。"
                "⚠ 危险操作：会触发确认弹窗；外部目标需授权。"
                "适合在 nmap/nikto 之后做广覆盖漏洞探测；命中项需人工验证。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标：URL（http://x）或 IP/CIDR/域名"},
                    "severity": {
                        "type": "string",
                        "enum": SEVERITIES,
                        "description": "最低严重级别（默认 medium，只报中危以上）",
                    },
                    "tags": {
                        "type": "string",
                        "description": "模板标签过滤，如 'cve,oast' 或 'tech'（技术指纹）",
                    },
                    "templates": {
                        "type": "string",
                        "description": "指定模板路径/ID（可选，如 cves/2023/CVE-2023-xxxx.yaml）",
                    },
                    "rate": {"type": "integer", "description": "每秒请求数限制（默认 100）"},
                },
                "required": ["target"],
            },
        },
    },
]

_TAG_RE = re.compile(r"^[a-z0-9_,-]{1,200}$")
_TEMPLATE_RE = re.compile(r"^[\w./-]{1,300}$")


def _build_cmd(args: dict[str, Any]) -> tuple[str, int]:
    target = str(args["target"]).strip()
    if target.startswith(("http://", "https://")):
        target = sanitize_url(target)
    else:
        target = sanitize_target(target)
    severity = str(args.get("severity") or "medium").strip().lower()
    if severity not in SEVERITIES:
        raise ValueError(f"severity 仅支持: {', '.join(SEVERITIES)}")
    tags = str(args.get("tags") or "").strip()
    if tags and not _TAG_RE.match(tags):
        raise ValueError(f"tags 格式非法: {tags!r}")
    templates = str(args.get("templates") or "").strip()
    if templates and not _TEMPLATE_RE.match(templates):
        raise ValueError(f"templates 格式非法: {templates!r}")
    rate = sanitize_int(args.get("rate"), 100, 1, 10000, "rate")

    parts = ["nuclei", "-u", target, "-severity", severity, "-rate-limit", str(rate)]
    if tags:
        parts += ["-tags", tags]
    if templates:
        parts += ["-t", templates]
    parts.append("-silent")
    return " ".join(parts), 600


def _summarize(raw: str) -> str:
    hits = [
        l.strip()
        for l in raw.splitlines()
        if re.search(r"\[(info|low|medium|high|critical)\]", l, re.IGNORECASE)
    ]
    if hits:
        head = [f"🎯 命中 {len(hits)} 条:"]
        head += hits[:30]
        if len(hits) > 30:
            head.append(f"… 共 {len(hits)} 条")
        head.append("下一步：对 high/critical 命中项人工验证（curl 复现），再评估利用。")
    else:
        head = ["未命中（可降低 severity 到 info/low 或加 tags 扩大覆盖面）"]
    return ToolProfile._summary(raw, head, tail=45)


class NucleiProfile(ToolProfile):
    name = "nuclei"
    aliases = ["nuclei", "模板扫描", "cve 扫描", "漏洞模板", "模板", "cve"]
    summary = "模板化漏洞扫描"
    lore = """### nuclei 深度使用要点
- 定位：nmap/nikto 之后做广覆盖漏洞探测；模板库庞大（CVE、暴露面板、配置错误、技术指纹）。
- severity 默认 medium 起报；想全面看 info（指纹）可降到 info，但噪音大。
- tags 技巧：`-tags tech` 识别技术栈（WordPress/nginx/Java…）；`-tags cve` 只看 CVE。
- 命中项是模板匹配结果，可能有误报：high/critical 必须人工 curl 复现确认。
- 大批量目标：先把 IP 列表写入文件用 `-l file`（当前封装支持单目标，批量可 run_command）。"""
    extra_schemas = SCHEMAS

    async def exec_nuclei_scan(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("nuclei"):
            return "nuclei 未安装（apt install nuclei 或 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest）。"
        cmd, timeout = _build_cmd(args)
        raw = await self._run(ex, cmd, timeout=timeout)
        return _summarize(raw)
